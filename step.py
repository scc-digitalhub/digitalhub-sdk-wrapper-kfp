# SPDX-FileCopyrightText: © 2025 DSLab - Fondazione Bruno Kessler
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import time
import typing

import digitalhub as dh
from digitalhub.entities._base.entity.entity import Entity
from digitalhub.entities._commons.enums import State
from digitalhub.utils.logger import LOGGER

if typing.TYPE_CHECKING:
    from digitalhub.entities._base.executable.entity import ExecutableEntity
    from digitalhub.entities.run._base.entity import Run


# default KFP artifacts and output (ui metadata, metrics etc.)
# directories to /tmp to allow running with security context
KFPMETA_DIR = "/tmp"
KFP_ARTIFACTS_DIR = "/tmp"


def _is_finished(state: str) -> bool:
    """
    Check if state is finished.

    Parameters
    ----------
    state : str
        The state to check.

    Returns
    -------
    bool
        True if the state is finished, False otherwise.
    """
    return state in (State.COMPLETED.value, State.ERROR.value, State.STOPPED.value)


def _is_complete(state: str) -> bool:
    """
    Check if state is complete.

    Parameters
    ----------
    state : str
        The state to check.

    Returns
    -------
    bool
        True if the state is complete, False otherwise.
    """
    return state == State.COMPLETED.value


def execute_step(exec_entity: ExecutableEntity, exec_kwargs: dict) -> None:
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

    Notes
    -----
    - Waits for the run to reach a finished state, polling every 5 seconds.
    - Writes the run ID to an output file named "run_id".
    - If the run completes successfully, writes output entities to files.
    - Logs all major steps and warnings for failures.
    - Exits with code 1 if the run fails.
    """
    LOGGER.info(f"Executing {exec_entity.ENTITY_TYPE} task {exec_kwargs['action']}")
    run = exec_entity.run(**exec_kwargs)

    _poller(run)

    # Write run_id to output file
    try:
        _write_output("run_id", run.id)
    except Exception as e:
        LOGGER.info(f"Failed writing run_id to temp file. Ignoring ({repr(e)})")

    # Process outputs
    _check_complete(run)
    LOGGER.info("Step completed: " + run.status.state)

    _export_outputs(run)
    LOGGER.info("Done.")


def _poller(run: Run) -> None:
    """
    Poll a run until it reaches a finished state.

    Parameters
    ----------
    run : Run
        The run to poll.

    Returns
    -------
    None

    Notes
    -----
    Polls the run every 5 seconds until it reaches a finished state.
    """
    while not _is_finished(run.status.state):
        time.sleep(5)
        run = run.refresh()
        LOGGER.info("Step state: " + run.status.state)


def _check_complete(run: Run) -> None:
    """
    Check if a run is complete and process outputs if it is.

    Parameters
    ----------
    run : Run
        The run to check.

    Returns
    -------
    None

    Notes
    -----
    - If the run is complete, writes the run ID to an output file named "run_id".
    - If the run completes successfully, writes output entities to files.
    - Logs all major steps and warnings for failures.
    - Exits with code 1 if the run fails.
    """
    if not _is_complete(run.status.state):
        LOGGER.info("Step failed: " + run.status.state)
        exit(1)


def _export_outputs(run: Run) -> None:
    """
    Export output entities from a run to a file in the KFP artifacts directory.

    Parameters
    ----------
    run : Run
        The run to export.

    Returns
    -------
    None

    Notes
    -----
    Prevents path traversal attacks by validating the output path.
    Logs warnings if writing fails or if the path is unsafe.
    """
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


def _write_output(key: str, value: str) -> None:
    """
    Write an output value to a file in the KFP artifacts directory.

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
    path = os.path.join(KFP_ARTIFACTS_DIR, key)
    if not _is_safe_path(KFP_ARTIFACTS_DIR, path):
        LOGGER.info(f"Path traversal is not allowed, ignoring: {path} / {key}")
        return
    path = os.path.abspath(path)
    LOGGER.info(f"Writing artifact output: {path}, value: {value}")
    try:
        with open(path, "w") as fp:
            fp.write(value)
        LOGGER.info(f"File written: {path}, size: {os.stat(path).st_size}")
    except Exception as e:
        LOGGER.info(f"Failed to write output file {path}: {repr(e)}")


def _is_safe_path(base: str, filepath: str, is_symlink: bool = False) -> bool:
    """
    Check if the given filepath is within the base directory to prevent path traversal.

    Parameters
    ----------
    base : str
        The base directory.
    filepath : str
        The file path to check.
    is_symlink : bool, optional
        Whether to resolve symlinks (default is False).

    Returns
    -------
    bool
        True if the filepath is safe, False otherwise.
    """
    resolved_filepath = os.path.abspath(filepath) if not is_symlink else os.path.realpath(filepath)
    return base == os.path.commonpath((base, resolved_filepath))


def _parse_exec_entity(args: argparse.Namespace) -> ExecutableEntity:
    """
    Parse the execution entity (function or workflow) from command-line arguments.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    ExecutableEntity
        The loaded function or workflow entity.

    Exits
    -----
    Exits the program if neither function nor workflow is specified.
    """
    LOGGER.info("Loading project " + args.project)
    project_entity = dh.get_project(args.project)

    if args.function is not None:
        LOGGER.info("Loading function " + args.function)
        return project_entity.get_function(args.function, entity_id=args.function_id)

    elif args.workflow is not None:
        LOGGER.info("Loading workflow " + args.workflow)
        return project_entity.get_workflow(args.workflow, entity_id=args.workflow_id)

    else:
        LOGGER.info("Step failed: no workflow or function defined")
        exit(1)


def _parse_exec_kwargs(args: argparse.Namespace) -> dict:
    """
    Parse execution keyword arguments from argparse arguments.

    This function collects action, inputs, parameters, outputs, and any additional
    properties provided as JSON. It supports multiple input/output/parameter
    arguments via repeated CLI flags.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    dict
        Dictionary of keyword arguments to be passed to the executable entity.

    Notes
    -----
    - The function expects CLI flags: -ie (inputs), -iv (parameters), -oe (outputs).
    - Additional properties can be passed as a JSON string via --jsonprops.
    - Later keys in --jsonprops will override previous ones if duplicated.
    """
    exec_kwargs = {"action": args.action}

    # Map CLI flags to exec_kwargs keys
    flag_map = [("ie", "inputs"), ("iv", "parameters"), ("oe", "outputs")]
    for cli_attr, kwarg_key in flag_map:
        props = _parse_properties(getattr(args, cli_attr, None))
        if props:
            exec_kwargs[kwarg_key] = props

    # Merge additional properties from JSON, if provided
    if getattr(args, "jsonprops", None):
        try:
            exec_kwargs.update(json.loads(args.jsonprops))
        except Exception as e:
            LOGGER.info(f"Failed to parse jsonprops: {e}")

    return exec_kwargs


def _parse_properties(str_list: list[str] | None) -> dict:
    """
    Parse a list of key=value strings into a dictionary.

    Parameters
    ----------
    str_list : list[str] or None
        List of strings in the form key=value.

    Returns
    -------
    dict
        Dictionary of parsed key-value pairs. Returns empty dict if input is None.
    """
    if not str_list:
        return {}
    result = {}
    for param in str_list:
        if "=" not in param:
            raise ValueError(f"Invalid property format (expected key=value): {param}")
        key, value = param.split("=", 1)
        result[key] = value
    return result


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Step executor")
    parser.add_argument("--project", type=str, help="Project reference", required=True)
    parser.add_argument("--function", type=str, help="Function name", required=False, default=None)
    parser.add_argument("--function_id", type=str, help="Function ID", required=False, default=None)
    parser.add_argument("--workflow", type=str, help="Workflow name", required=False, default=None)
    parser.add_argument("--workflow_id", type=str, help="Workflow ID", required=False, default=None)
    parser.add_argument("--action", type=str, help="Action type", required=False, default=None)
    parser.add_argument("--jsonprops", type=str, help="Function kwargs (as JSON)", required=False)
    parser.add_argument("--parameters", type=str, help="Function parameters", required=False)
    parser.add_argument("-ie", action="append", type=str, help="Input entity property", required=False)
    parser.add_argument("-iv", action="append", type=str, help="Input parameters property", required=False)
    parser.add_argument("-oe", action="append", type=str, help="Output entity property", required=False)
    return parser


def main():
    """
    Main function. Get run from backend and execute function.
    """
    args = parser().parse_args()
    exec_kwargs = _parse_exec_kwargs(args)
    exec_entity = _parse_exec_entity(args)
    execute_step(exec_entity, exec_kwargs)


if __name__ == "__main__":
    main()
