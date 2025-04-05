from mcp.server.fastmcp import FastMCP
import requests
import base64

burpsuite_server_url = "http://localhost:8889"

mcp = FastMCP("burpsuite-mcp")

ALLOWED_FIELDS = [
    "req",
    "req.content_type",
    "req.body",
    "host",
    "url",
    "method",
    "resp",
    "resp.content_type",
    "resp.body",
    "status_code"
]

Allowed_Operators = ["=", ">", "<", "like", "!="]

NOT_ALLOWED = ["SELECT", "FROM", "WHERE", "LIMIT"]

@mcp.tool()
def query_history(fields: list,conditions: str, limit: int = 20):
    """
    Query the history of Burp Suite with multiple conditions.

    Args:
        fields (list): list of fields to select.Here are the allowed fields: 
            "req": raw string request
            "req.content_type": content type of request, string
            "req.body": raw string request body
            "host": host of request, string, no port
            "url": url of request, string
            "method": method of request, string, e.g. 'GET', 'POST'
            
            "resp": raw string response
            "resp.content_type": content type of response, string
            "resp.body": raw string response body
            "resp.status_code": status code of response, int    
        conditions (str): SQL-style conditions, e.g. "req.content_type='text/html' and  resp.status_code=200"
            conditions operator:
            = : means equal
            > : means greater than
            < : means less than
            != : means not equal
            like: means contains, do not add '%' in like condition
            
            
        limit (int): the limit of the result.If not specified, 20 will be used.

    Example:
        query the url and request of Burp Suite history which:
        1. request content type is 'JSON'
        2. response status code is 200
        3. request body contains 'password'
        4. limit 10
        
        query_history(["url", "req"], "req.content_type='application/json' and status_code=200 and req.body like 'password'", 10) 
    """

    (is_validate, error_msg) = check_input(fields, conditions, limit)
    if not is_validate:
        return error_msg
    params = {
        "fields": ",".join(fields),
        "conditions": conditions,
        "limit": limit
    }
    return safe_post("query", params)




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


def safe_post(endpoint: str, params: dict) -> list:
    url = f"{burpsuite_server_url}/{endpoint}"

    data = f"SELECT {params['fields']} FROM proxy WHERE {params['conditions']} LIMIT {params['limit']}"
    base64_data = {"query": base64.b64encode(data.encode('utf-8')).decode('utf-8')}
    try:
        response = requests.post(url, data=base64_data, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.json()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def check_input(fields: list, conditions: str, limit: int = 20) -> (bool, str):
    """
    Validate the input parameters.
    1. Both fields and conditions input can not contain SQL keywords: SELECT, FROM, WHERE, LIMIT
    2. For fields, only allowed fields are: ALLOWED_FIELDS
    3. For conditions, only allowed operators are: =, >, <, like, !=
    4. limit must be a positive integer

    return True if validate, False and error message if not
    """
    error_msg:str
    is_valid:bool = False


    for not_allowed in NOT_ALLOWED:
        for field in fields:
            if not_allowed in field.strip().upper():
                return (False, f"Invalid field: {field}")

        if not_allowed in conditions.strip().upper():
            return (False, f"Invalid condition: {conditions}")

    for field in fields:
        if field.strip() not in ALLOWED_FIELDS:
            return (False, f"Invalid field: {field}")

    # check operators in Burp suite extension
    
    if limit < 0:
        return (False, f"Invalid limit: {limit}")
    
    return (True, "")
    

if __name__ == "__main__":
    mcp.run()