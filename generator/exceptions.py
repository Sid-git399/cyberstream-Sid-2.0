from common.errors import AppError


class ScenarioError(AppError):
    code = "SCENARIO_ERROR"
    http_status = 400


class UnknownScenarioError(ScenarioError):
    code = "UNKNOWN_SCENARIO"

    def __init__(self, scenario_name: str, available: list[str]):
        super().__init__(
            f"Unknown scenario '{scenario_name}'. Available: {', '.join(available)}",
            details={"requested": scenario_name, "available": available},
        )
