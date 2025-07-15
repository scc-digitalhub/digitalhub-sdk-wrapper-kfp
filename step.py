# SPDX-FileCopyrightText: © 2025 DSLab - Fondazione Bruno Kessler
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import typing

import digitalhub as dh
from digitalhub.entities._base.entity.entity import Entity
from digitalhub.entities._commons.enums import EntityTypes, State
from digitalhub.entities._commons.utils import parse_entity_key
from digitalhub.utils.logger import LOGGER

if typing.TYPE_CHECKING:
    from digitalhub.entities._base.executable.entity import ExecutableEntity
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

    Returns
    -------
    None

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

    Returns
    -------
    None
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


def _parse_exec_entity(entity_key: str) -> ExecutableEntity:
    """
    Parse the executable entity from command-line arguments.

    Parameters
    ----------
    entity_key : str
        The key of the executable entity.

    Returns
    -------
    ExecutableEntity
        The parsed executable entity.
    """
    _, entity_type, _, name, uuid = parse_entity_key(entity_key)
    LOGGER.info(f"Getting {entity_type} {name}:{uuid}.")
    if entity_type == EntityTypes.FUNCTION.value:
        return dh.get_function(entity_key)
    elif entity_type == EntityTypes.WORKFLOW.value:
        return dh.get_workflow(entity_key)
    LOGGER.info("Step failed: no workflow or function defined")
    exit(1)


def execute_step(
    exec_entity: ExecutableEntity,
    exec_kwargs: dict,
) -> None:
    """
    Execute a step by running the provided executable entity with the given arguments.
    Waits for the execution to finish, writes the run ID to an output file,
    and processes and writes any output entities if the run completes successfully.

    Parameters
    ----------
    exec_entity : ExecutableEntity
        The executable entity to run (function or workflow).
    exec_kwargs : dict
        The keyword arguments to pass to the entity's run method.

    Returns
    -------
    None
    """
    # Run
    LOGGER.info(f"Executing {exec_entity.ENTITY_TYPE} {exec_entity.name}:{exec_entity.id}")
    run = exec_entity.run(**exec_kwargs)

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
    parser.add_argument("--entity", type=str, help="Executable entity key", required=True)
    parser.add_argument("--kwargs", type=str, help="Execution keyword arguments", required=True)

    args = parser.parse_args()
    exec_entity = _parse_exec_entity(args.entity)
    exec_kwargs = json.loads(args.kwargs)
    execute_step(exec_entity, exec_kwargs)


if __name__ == "__main__":
    main()
