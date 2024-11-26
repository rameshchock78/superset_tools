import jwt
import time
import uuid
import requests
import argparse

class SupersetServiceManager:
    # Class-level constants for API paths
    LOGIN_PATH = '/api/v1/security/login'
    CSRF_PATH = '/api/v1/security/csrf_token/'
    CHART_DATA_PATH = '/api/v1/chart/data'
    DATASET_PATH = '/api/v1/dataset/'
    EXPLORE_PATH = '/api/v1/explore/'
    COLUMN_VALUE_PATH = '/api/v1/datasource/table'
    DATABASE_PATH = '/api/v1/database/'
    SQLLAB_PATH = '/api/v1/sqllab/'
    SAVED_QUERY_PATH = '/api/v1/saved_query/'
    QUERY_PATH = '/api/v1/query/'

    def __init__(self, superset_audience_url, superset_base_url, superset_issuer_url, key_secret):
        """
        Initialize the SupersetServiceManager with required configurations.
        """
        self.audience_url = superset_audience_url
        self.base_url = superset_base_url
        self.issuer_url = superset_issuer_url
        self.key_secret = key_secret

    def generate_tokens(self, user_email):
        """
        Generates access and CSRF tokens for the given user_email.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ZETAToken": self.generate_jwt_token(user_email)
        }

        data = {
            "username": user_email,
            "refresh": True,
            "provider": "oauth"
        }

        # Login request to generate access token
        login_url = f"{self.base_url}{self.LOGIN_PATH}"
        response = requests.post(login_url, headers=headers, json=data)

        if response.status_code == 200:
            response_data = response.json()
            auth_token = response_data.get("access_token")

            # Get CSRF token using the access token
            csrf_response = self.get_csrf_token(auth_token)
            if "error" in csrf_response:
                return {"error": csrf_response["error"], "code": csrf_response["code"]}

            return {
                "auth_token": auth_token,
                "csrf_token": csrf_response["token"],
                "cookie": csrf_response["session"]
            }
        else:
            return {"error": response.text, "code": response.status_code}

    def get_csrf_token(self, access_token):
        """
        Fetches the CSRF token and session cookies using the access token.
        """
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}"
        }

        csrf_url = f"{self.base_url}{self.CSRF_PATH}"
        response = requests.get(csrf_url, headers=headers)
        if response.status_code != 200:
            return {"error": response.text, "code": response.status_code}

        parsed_response = response.json()
        return {
            "token": parsed_response.get("result"),
            "session": response.cookies.get("session")
        }

    def generate_jwt_token(self, user_email):
        """
        Generates a JWT token for the given user_email.
        """
        issued_at = int(time.time())  # Current UTC time in seconds
        expires_at = issued_at + (15 * 60)  # Token expiry time: 15 minutes
        payload = {
            "sub": user_email,
            "aud": self.audience_url,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "jti": str(uuid.uuid4()),
            "iss": self.issuer_url
        }

        # Encode the payload with the provided key_secret
        encoded_data = jwt.encode(payload, self.key_secret, algorithm="HS256")
        return encoded_data

    def get_chart_data(self, user_email: str):
        """
        Fetch chart data with a user_email parameter and payload-based queries.
        """
        # Log the intent
        print(f"Fetching chart data for user_email: {user_email}")

        # Construct the URL with user_email as a query parameter
        chart_data_url = f"{self.base_url}{self.CHART_DATA_PATH}?user_email={user_email}"

        # Generate tokens
        tokens = self.generate_tokens(user_email)
        if "error" in tokens:
            raise ValueError(f"Error while generating tokens: {tokens['error']} (Code: {tokens['code']})")

        auth_token = tokens["auth_token"]
        csrf_token = tokens["csrf_token"]

        # Request headers
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRFToken": csrf_token,
        }

        # Data payload for the chart query
        payload = {
            "datasource": {"id": 112, "type": "table"},
            "force": False,
            "queries": [
                {
                    "filters": [{"col": "day", "op": "TEMPORAL_RANGE", "val": "Last week"}],
                    "extras": {"time_grain_sqla": "P1D", "having": "", "where": ""},
                    "applied_time_extras": {},
                    "columns": [
                        {"timeGrain": "P1D", "columnType": "BASE_AXIS", "sqlExpression": "day", "label": "day",
                         "expressionType": "SQL"},
                        "delivery_channel",
                    ],
                    "metrics": ["media_cost"],
                    "orderby": [["media_cost", False]],
                    "annotation_layers": [],
                    "row_limit": 1000,
                    "series_limit": 0,
                    "order_desc": True,
                    "url_params": {"datasource_id": "112", "datasource_type": "table"},
                    "custom_params": {},
                    "custom_form_data": {},
                    "post_processing": [],
                }
            ],
            "form_data": {
                "datasource": "112__table",
                "viz_type": "table",
                "url_params": {"datasource_id": "112", "datasource_type": "table"},
                "query_mode": "aggregate",
                "groupby": ["day", "delivery_channel"],
                "time_grain_sqla": "P1D",
                "temporal_columns_lookup": {"day_campaign_timezone": True, "refresh_time": True, "day": True},
                "metrics": ["media_cost"],
                "row_limit": 1000,
                "server_page_length": 10,
                "order_desc": True,
                "result_format": "json",
                "result_type": "full",
            },
            "result_format": "json",
            "result_type": "full",
        }

        # Make the POST request to fetch chart data
        response = requests.post(chart_data_url, json=payload, headers=headers)

        # Log response
        print(f"get_chart_data: {response.status_code}, {response.text}")

        # Check for errors in the response
        if response.status_code != 200:
            msg = f"Failed to fetch chart data. Status code: {response.status_code}, Response: {response.text}"
            raise ValueError(msg)

        # Parse and return the response JSON
        chart_data = response.json()

        # Extract the SQL query and data from the chart_data response
        if 'result' in chart_data:
            sql_query = chart_data['result'][0].get('query', 'No query available')
            data = chart_data['result'][0].get('data', [])

            # Print the SQL query
            print("SQL Query:\n")
            print(sql_query)

            # Print the formatted data
            print("\nFormatted Data:\n")
            for row in data:
                # Format the row data for readability
                formatted_row = {key: f"{value:.2f}" if isinstance(value, float) else value for key, value in
                                 row.items()}
                print(formatted_row)

        else:
            print("No result data available in the response.")

        # print(f"Chart data fetched successfully: {chart_data}")
        return chart_data


# Usage example
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Superset API caller Script")
    parser.add_argument("user_email", help="The email of the user for SSO authentication")
    parser.add_argument("key_secret", help="The key secret for authentication")

    args = parser.parse_args()
    # Superset configuration values
    superset_audience_url = "https://phoenix.app.zetaglobal.net/"
    superset_base_url = "https://zeta-superset.phoenix.zglbl.net"
    superset_issuer_url = "https://issuer.phoenix.app.zetaglobal.net/"
    key_secret = args.key_secret

    # User email for the SSO authentication
    user_email = args.user_email

    # Initialize the service manager
    superset_manager = SupersetServiceManager(
        superset_audience_url,
        superset_base_url,
        superset_issuer_url,
        key_secret
    )

    # Generate tokens
    tokens = superset_manager.generate_tokens(user_email)
    if "error" in tokens:
        print(f"Error: {tokens['error']} (Code: {tokens['code']})")
    else:
        print("Auth Token:", tokens["auth_token"])
        print("CSRF Token:", tokens["csrf_token"])
        print("Session Cookie:", tokens["cookie"])

        # Example: Fetch chart data
        chart_data = superset_manager.get_chart_data(user_email)
        if "error" in chart_data:
            print(f"Chart Data Error: {chart_data['error']} (Code: {chart_data['code']})")
