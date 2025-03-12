import json
import subprocess
import sys
import os
from typing import Any, Dict


def get_terraform_output(output_name: str) -> Any:
    """Fetch Terraform output as JSON and return the value."""
    try:
        result = subprocess.run(
            ["terraform", "output", "-json", output_name],
            capture_output=True,
            text=True,
            check=True,
        )
        output = json.loads(result.stdout)
        return output.get("value", output) if isinstance(output, dict) else output
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(
            f"❌ Error fetching Terraform output '{output_name}': {e}", file=sys.stderr
        )
        sys.exit(1)


def load_config(path: str) -> Dict:
    """Load Chalice config JSON file."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"❌ Error loading Chalice config '{path}': {e}", file=sys.stderr)
        sys.exit(1)


def save_config(config: Dict, path: str) -> None:
    """Atomically save Chalice config JSON file."""
    temp_path = f"{path}.tmp"
    try:
        with open(temp_path, "w") as f:
            json.dump(config, f, indent=2)
        os.replace(temp_path, path)
    except IOError as e:
        print(f"❌ Error saving Chalice config '{path}': {e}", file=sys.stderr)
        sys.exit(1)


def update_chalice_config() -> None:
    """Update `.chalice/config.json` with Terraform outputs, environment variables, and Lambda layer ARN."""
    config_path = ".chalice/config.json"

    # Fetch required Terraform outputs
    terraform_outputs = {"lambda_role_arn": get_terraform_output("lambda_role_arn")}

    # Required environment variables
    required_env_vars = [
        "COGNITO_USER_POOL_ID",
        "COGNITO_USER_POOL_NAME",
        "COGNITO_USER_POOL_ARN",
        "COGNITO_USER_POOL_DOMAIN",
        "COGNITO_APP_CLIENT_ID",
        "COGNITO_APP_CLIENT_SECRET",
        "COGNITO_APP_CLIENT_NAME",
        "API_GATEWAY_INVOKE_URL",
        "API_FRONTEND_URL",
        "SECRET_KEY",
    ]

    # Validate and collect environment variables
    env_vars = {var: os.getenv(var) for var in required_env_vars}
    missing_env_vars = [var for var, value in env_vars.items() if value is None]

    if missing_env_vars:
        print(
            f"❌ Missing required environment variables: {', '.join(missing_env_vars)}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load Chalice config
    config = load_config(config_path)

    # Apply Terraform and environment variables to Chalice config
    try:
        config["stages"]["dev"]["iam_role_arn"] = terraform_outputs["lambda_role_arn"]
        config["stages"]["dev"]["environment_variables"].update(env_vars)

    except KeyError as e:
        print(f"❌ Error updating Chalice config: Missing key {e}", file=sys.stderr)
        sys.exit(1)

    # Save updated config
    save_config(config, config_path)
    print("✅ Successfully updated Chalice configuration.")


if __name__ == "__main__":
    update_chalice_config()
