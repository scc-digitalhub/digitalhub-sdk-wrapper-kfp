# SPDX-FileCopyrightText: © 2025 DSLab - Fondazione Bruno Kessler
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import typing

from digitalhub.entities._base.entity.entity import Entity
from digitalhub.entities._commons.enums import Relationship, State
from digitalhub.entities.function.crud import get_function
from digitalhub.entities.run.crud import get_run
from digitalhub.factory.entity import entity_factory
from digitalhub.runtimes.enums import RuntimeEnvVar
from digitalhub.utils.logger import LOGGER

if typing.TYPE_CHECKING:
    from digitalhub.entities.function._base.entity import Function
    from digitalhub.entities.run._base.entity import Run


def _write_output(key: str, value: str) -> None:
    """
    Write an output value to a file in the Hera artifacts directory.

    Parameters
    ----------
    key : str
        The output key, used as the filename.
    value : str
        The value to write to the file.

    Notes
    -----
    Prevents path traversal attacks by validating the output path.
    Logs warnings if writing fails or if the path is unsafe.
    """
    base = "/tmp"
    path = os.path.join(base, key)

    # Check if the path is safe
    if not base == os.path.commonpath((base, os.path.abspath(path))):
        LOGGER.info(f"Path traversal is not allowed, ignoring: {path} / {key}")
        return

    # Write the file
    path = os.path.abspath(path)
    LOGGER.info(f"Writing artifact output: {path}, value: {value}")
    try:
        with open(path, "w") as fp:
            fp.write(value)
        LOGGER.info(f"File written: {path}, size: {os.stat(path).st_size}")
    except Exception as e:
        LOGGER.info(f"Failed to write output file {path}: {repr(e)}")


def _export_outputs(run: Run) -> None:
    """
    Export outputs from a run.

    Parameters
    ----------
    run : Run
        The run to export.
    """
    try:
        _write_output("run_id", run.id)
    except Exception as e:
        LOGGER.info(f"Failed writing run_id to temp file. Ignoring ({repr(e)})")

    if not hasattr(run, "outputs"):
        return

    # Process output entities
    results = {}
    for prop, val in run.outputs().items():
        target_output = f"entity_{prop}"
        # Extract key or value depending on type
        if isinstance(val, str):
            results[target_output] = val
        elif isinstance(val, Entity):
            results[target_output] = val.key
        elif isinstance(val, dict) and "key" in val:
            results[target_output] = val["key"]
        else:
            LOGGER.info(f"Unknown output type for {prop}: {type(val)}")
            continue

    for key, value in results.items():
        _write_output(key, value)


def _parse_exec_entity(entity_key: str) -> Function:
    """
    Parse the executable entity from command-line arguments.

    Parameters
    ----------
    entity_key : str
        The key of the executable entity.

    Returns
    -------
    Function
        The executable entity (function).
    """
    LOGGER.info(f"Getting function {entity_key}.")
    try:
        return get_function(entity_key)
    except Exception as e:
        LOGGER.info(f"Step failed: Error getting function: {str(e)}")
        exit(1)


def execute_step(
    func: Function,
    exec_kwargs: dict,
) -> None:
    """
    Execute a step by running the provided executable entity with the given arguments.
    Waits for the execution to finish, writes the run ID to an output file,
    and processes and writes any output entities if the run completes successfully.

    Parameters
    ----------
    exec_entity : Function
        The executable entity to run (function).
    exec_kwargs : dict
        The keyword arguments to pass to the entity's run method.
    """
    # Run
    LOGGER.info(f"Executing {func.ENTITY_TYPE} {func.name}:{func.id}")

    # Get workflow run id from run env var
    workflow_run_id = os.getenv(RuntimeEnvVar.RUN_ID.value)
    project = os.getenv(RuntimeEnvVar.PROJECT.value)
    workflow_run = get_run(workflow_run_id, project=project)
    workflow_run_key = workflow_run.key + ":" + workflow_run.id

    # Get task and run kind
    action = exec_kwargs.pop("action", None)
    if action is None:
        LOGGER.info("Step failed: action argument is required.")
        exit(1)

    task_kind = entity_factory.get_task_kind_from_action(func.kind, action)
    run_kind = entity_factory.get_run_kind_from_action(func.kind, action)

    # Create or update new task
    task = func._get_or_create_task(task_kind)

    # Remove execution flags
    exec_kwargs.pop("local_execution", None)
    exec_kwargs.pop("wait", None)

    # Create run from task
    run = task.run(run_kind, save=False, local_execution=False, **exec_kwargs)

    # Set as run's parent and workflow relationship
    run.add_relationship(Relationship.STEP_OF.value, workflow_run_key)
    run.add_relationship(Relationship.RUN_OF.value, func.key)
    run.save()
    run.wait()

    # Check for errors
    if run.status.state == State.ERROR.value:
        LOGGER.info("Step failed: " + run.status.state)
        exit(1)

    LOGGER.info("Step ended with state: " + run.status.state)

    # Write run_id and outputs
    _export_outputs(run)
    LOGGER.info("Done.")


def main() -> None:
    """
    Main function.
    """
    parser = argparse.ArgumentParser(description="Step executor")
    parser.add_argument(
        "--entity",
        type=str,
        help="Executable entity key",
        required=True,
    )
    parser.add_argument(
        "--kwargs",
        type=str,
        help="Execution keyword arguments",
        required=True,
    )

    args = parser.parse_args()
    exec_entity = _parse_exec_entity(args.entity)
    exec_kwargs = json.loads(args.kwargs)
    execute_step(exec_entity, exec_kwargs)


if __name__ == "__main__":
    main()
