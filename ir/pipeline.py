"""IR Pipeline - Pass Manager"""

from typing import Any, List


class Pass:
    """Pass base class"""

    def run(self, input_data: Any) -> Any:
        """Execute the pass"""
        raise NotImplementedError(f'{self.__class__.__name__}.run() not implemented')


class Pipeline:
    """Pass Pipeline"""

    def __init__(self, passes: List[Pass] = None):
        """Initialize pipeline"""
        self.passes = passes or []

    def add_pass(self, pass_obj: Pass) -> 'Pipeline':
        """Add a pass to the pipeline"""
        self.passes.append(pass_obj)
        return self

    def run(self, input_data: Any, debug: bool = False) -> Any:
        """Run all passes in the pipeline"""
        result = input_data
        for pass_obj in self.passes:
            if debug:
                print(f'  Running {pass_obj.__class__.__name__}...')
            result = pass_obj.run(result)
            if debug:
                print(f'  {pass_obj.__class__.__name__} done')
        return result
