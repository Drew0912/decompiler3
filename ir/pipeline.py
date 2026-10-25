"""IR Pipeline - Pass Manager"""

from typing import Any

from dc3.logging import log


class Pass:
    """Pass base class"""

    def run(self, input_data: Any) -> Any:
        """Execute the pass"""
        raise NotImplementedError(f'{self.__class__.__name__}.run() not implemented')


class Pipeline:
    """Pass Pipeline"""

    def __init__(self, passes: list[Pass] = None):
        """Initialize pipeline"""
        self.passes = passes or []

    def add_pass(self, pass_obj: Pass):
        """Add a pass to the pipeline"""
        self.passes.append(pass_obj)

    def run(self, input_data: Any, debug: bool = False) -> Any:
        """Run all passes in the pipeline; with debug, log when each pass starts and ends"""
        result = input_data
        for pass_obj in self.passes:
            if debug:
                log.info(f'Running {pass_obj.__class__.__name__}...')
            result = pass_obj.run(result)
            if debug:
                log.info(f'{pass_obj.__class__.__name__} done')
        return result
