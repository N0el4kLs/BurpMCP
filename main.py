from mcp.server.fastmcp import FastMCP
import requests

burpsuite_server_url = "http://localhost:8889"

mcp = FastMCP("burpsuite-mcp")


@mcp.tool()
def query_history(conditions: list, limit: int):
    """
    Query the history of Burp Suite with multiple conditions.

    Args:
        conditions (list): list of dictionaries, each containing 'location' and 'condition' keys.
                            allowed locations: "req", "resp", "url", "path", "body"
                          e.g. [{"location": "url", "condition": "example.com"}, 
                                {"location": "body", "condition": "password"}]
        limit (int): the limit of the result
    """
    params = {
        "conditions": conditions,
        "limit": limit
    }
    return safe_get("queryHistory", params)



def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request. If 'params' is given, we convert it to a query string.
    """
    if params is None:
        params = {}
        
    url = f"{burpsuite_server_url}/{endpoint}"
    try:
        response = requests.post(url, json=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.json()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


if __name__ == "__main__":
    mcp.run()