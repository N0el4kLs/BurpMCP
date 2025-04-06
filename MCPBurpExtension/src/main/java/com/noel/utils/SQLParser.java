package com.noel.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class SQLParser {
    private String[] selectFields;
    private List<String> whereConditions;
    private int limit;
    private final MontoyaApi api;

    private static final Pattern LEN_PATTERN = Pattern.compile("len\\(([^)]+)\\)\\s*(>|<|>=|<=|!=|=)\\s*(\\d+)");
    private static final Pattern CONDITION_PATTERN = Pattern.compile("((?:req|resp)?(?:\\.|\\w+\\.)?\\w+)\\s*(=|like|!=|>=|<=|>|<)\\s*(?:'([^']*)'|\"([^\"]*)\"|([^\\s]+))");
    private static final List<String> SUPPORTED_OPERATORS = Arrays.asList("=", "!=", "like", ">", "<");
    private final HashMap<String, Function<ProxyHttpRequestResponse, Object>> fieldExtractors;

    private static class Condition {
        String key;
        String operator;
        Object value;
        boolean isLengthCheck = false;
    }

    public SQLParser(String sql, MontoyaApi api) {
        this.api = api;
        fieldExtractors = new HashMap<>();

        registerFieldExtractor("req", rr -> rr.request().toString());
        registerFieldExtractor("host", rr -> rr.request().httpService().host());
        registerFieldExtractor("url", rr -> rr.request().url());
        registerFieldExtractor("method", rr -> rr.request().method().toUpperCase());
        registerFieldExtractor("req.content_type", rr -> rr.request().contentType());
        registerFieldExtractor("req.body", rr -> rr.request().bodyToString());

        registerFieldExtractor("resp", rr -> {
            if (rr.response() == null) {
                return null;
            }
            return rr.response().toString();
        });
        registerFieldExtractor("status_code", rr -> {
            if (rr.response() == null) {
                return null;
            }
            return rr.response().statusCode();
        });
        registerFieldExtractor("resp.content_type", rr -> {
            if (rr.response() == null) {
                return null;
            }
            return rr.response().mimeType().description();
        });
        registerFieldExtractor("resp.body", rr -> {
            if (rr.response() == null) {
                return null;
            }
            return rr.response().bodyToString();
        });


        parseSQL(sql);
    }

    public String[] getSelectFields() {
        return selectFields;
    }

    public List<String> getWhereConditions() {
        return whereConditions;
    }

    public int getLimit() {
        return limit;
    }


    @Deprecated
    public List<ProxyHttpRequestResponse> executeQuery() {
        List<ProxyHttpRequestResponse> filteredHistory = filterHistoryByConditions(this.getWhereConditions());
        if (this.getLimit() > 0 && filteredHistory.size() > this.getLimit()) {
            filteredHistory = filteredHistory.subList(0, this.getLimit());
        }

        return filteredHistory;
        // 处理选定的字段
//        return processSelectedFields(filteredHistory, this.getSelectFields());
    }

    /**
     * filter the proxy history with SQL style condition
     * @return List<ProxyHttpRequestResponse>
     */
    public List<ProxyHttpRequestResponse> filterHistoryBySQL() {
        List<ProxyHttpRequestResponse> allHistory = this.api.proxy().history();
        // Reverse the order of the history to match latest item all the time.
        Collections.reverse(allHistory);

        List<String> conditions = this.getWhereConditions();

        // Do not allow empty conditions, if you want to get all history, use method: this.getAllHistory()
        if (conditions == null || conditions.isEmpty()) {
            throw new IllegalArgumentException("Cannot parse the SQL query, missing where clause");
        }

        List<ProxyHttpRequestResponse> filteredHistory = new ArrayList<>();
        HashMap<byte[],String> uniqueMap = new HashMap<>();

        for (ProxyHttpRequestResponse proxyRequestOrResponse : allHistory) {
            if (filteredHistory.size() > this.getLimit()-1){
                break;
            }

            // Check if the request matches all conditions
            boolean isMatch = false;
            for (String condition : conditions) {
                if (!evaluateCondition(condition.trim(), proxyRequestOrResponse)) {
                    isMatch = false;
                    break;
                }
                isMatch = true;
            }
            if (!isMatch) {
                continue;
            }
            byte[] reqHash = calcRequestHash(proxyRequestOrResponse);
            if (uniqueMap.containsKey(reqHash)){
                continue;
            }
            uniqueMap.put(reqHash,proxyRequestOrResponse.request().url());
            filteredHistory.add(proxyRequestOrResponse);
        }

        return filteredHistory;
    }

    public List<ProxyHttpRequestResponse> getAllHistory() {
        return api.proxy().history();
    }

    /**
     * Process the selected fields from the filtered history
     */
    public List<Map<String, Object>> processSelectedFields(List<ProxyHttpRequestResponse> history, String[] fields) {
        return history.stream().map(item -> {
            Map<String, Object> result = new HashMap<>();
            for (String field : fields) {
                String fieldLower = field.toLowerCase();
                if (fieldExtractors.containsKey(fieldLower)) {
                    result.put(fieldLower, fieldExtractors.get(fieldLower).apply(item));
                }
            }
            return result;
        }).collect(Collectors.toList());
    }

    private void registerFieldExtractor(String fieldName, Function<ProxyHttpRequestResponse, Object> extractor) {
        fieldExtractors.put(fieldName.toLowerCase(), extractor);
    }

    // // Parse the SQL query and extract the select fields, where conditions, and limit
    private void parseSQL(String sql) {
        sql = sql.trim();

        // parse the select fields
        int selectIndex = sql.indexOf("SELECT ");
        int fromIndex = sql.indexOf(" FROM ");

        if (selectIndex == -1 || fromIndex == -1 || selectIndex > fromIndex) {
            throw new IllegalArgumentException("Cannot parse the SQL query, missing select or from clause");
        }
        String selectClause = sql.substring(selectIndex + 7, fromIndex).trim();
        selectFields = selectClause.split("\\s*,\\s*");

        // parse the where conditions
        whereConditions = new ArrayList<>();
        int whereIndex = sql.indexOf(" WHERE ");
        int limitIndex = sql.indexOf(" LIMIT ");

        String whereClause = "";
        if (whereIndex != -1) {
            whereClause = limitIndex != -1
                    ? sql.substring(whereIndex + 7, limitIndex).trim()
                    : sql.substring(whereIndex + 7).trim();

            // split the where conditions by 'and'
            String[] conditions = whereClause.split("\\s+and\\s+");
            whereConditions = new ArrayList<>(List.of(conditions));
        }

        // parse the limit
        if (limitIndex != -1) {
            try {
                limit = Integer.parseInt(sql.substring(limitIndex + 7).trim());
            } catch (NumberFormatException e) {
                limit = 1;
            }
        }

        // Log the parsed SQL query
        api.logging().logToOutput("[Info] Parsed SQL query:");
        api.logging().logToOutput("Select fields: " + String.join(", ", selectFields));
        api.logging().logToOutput("Where conditions: " + String.join(", ", whereConditions));
        api.logging().logToOutput("Limit: " + limit);
    }


    /**
     * Todo this logic is not correct, need to fix it later
     * Calculate the hash of the request to identify unique requests
     * @return byte[]
     */
    private byte[] calcRequestHash(ProxyHttpRequestResponse proxyRequestOrResponse) {
        String method = proxyRequestOrResponse.request().method();
        String url = proxyRequestOrResponse.request().url();
        String query = proxyRequestOrResponse.request().query();
        String body = proxyRequestOrResponse.request().bodyToString();

        String urlWithoutQuery;
        try{
            urlWithoutQuery = url.split(query)[0];
        }catch (IndexOutOfBoundsException e){
            urlWithoutQuery = url;
        }

        String reqIdentifier = method + urlWithoutQuery + query + body;
        byte[] identifierHash = null;
        try{
            MessageDigest message =  MessageDigest.getInstance("MD5");
            identifierHash =  message.digest(reqIdentifier.getBytes());
        }catch (NoSuchAlgorithmException e){
            this.api.logging().logToError("[Error] Error calculating request hash", e);
        }

        return identifierHash;
    }

    /**
     * Filter the history by conditions
     */
    @Deprecated
    private List<ProxyHttpRequestResponse> filterHistoryByConditions(List<String> conditions) {
        if (conditions == null || conditions.isEmpty()) {
            return this.api.proxy().history();
        }

        return this.api.proxy().history(proxyRequestOrResponse -> {
            for (String condition : conditions) {
                if (!evaluateCondition(condition.trim(), proxyRequestOrResponse)) {
                    return false;
                }
            }
            return true;
        });
    }


    /**
     * Evaluate the condition against the request or response
     * @return true if the condition is met, false otherwise
     */
    private boolean evaluateCondition(String condition, ProxyHttpRequestResponse request) {
        Condition parsedCondition = parseCondition(condition);
        if (parsedCondition == null) {
            return false;
        }

        if (parsedCondition.isLengthCheck) {
            return evaluateLengthCondition(parsedCondition, request);
        } else {
            return evaluateStandardCondition(parsedCondition, request);
        }
    }

    /**
     * Parse the condition string and extract the key, operator, and value
     */
    private Condition parseCondition(String condition) {
        Condition result = new Condition();

        // Handle length conditions
        Matcher lenMatcher = LEN_PATTERN.matcher(condition);
        if (lenMatcher.find()) {
            result.isLengthCheck = true;
            result.key = lenMatcher.group(1).trim().toLowerCase();
            result.operator = lenMatcher.group(2).trim();
            if (!SUPPORTED_OPERATORS.contains(result.operator)) {
                throw new IllegalArgumentException("Unsupported operator: " + result.operator);
            }
            result.value = lenMatcher.group(3).trim();
            return result;
        }

        // Handle standard conditions
        Matcher condMatcher = CONDITION_PATTERN.matcher(condition);
        if (condMatcher.find()) {
            result.isLengthCheck = false;
            result.key = condMatcher.group(1).trim().toLowerCase();
            result.operator = condMatcher.group(2).trim();
            if (!SUPPORTED_OPERATORS.contains(result.operator)) {
                throw new IllegalArgumentException("Unsupported operator: " + result.operator);
            }

            // Handle quoted values (single or double quotes) or unquoted values
            String tmpValue = condMatcher.group(3) != null ? condMatcher.group(3) :
                    condMatcher.group(4) != null ? condMatcher.group(4) :
                            condMatcher.group(5);

            result.value = tmpValue;
            tmpValue = tmpValue.toLowerCase();
            // Todo this is not the perfect way to find corresponding ContentType or MimeType
            switch (result.key){
                case "req.content_type":
                {
                    if (tmpValue.contains("json") || tmpValue.contains("application/json")){
                        result.value = ContentType.JSON;
                    } else if (tmpValue.contains("xml")){
                        result.value = ContentType.XML;
                    }else {
                        throw new IllegalArgumentException("Unsupported request content type: " + tmpValue);
                    }
                    break;
                }
                case "resp.content_type":
                {
                    if (tmpValue.contains("json")){
                        result.value = MimeType.JSON.description();
                    }else if (tmpValue.contains("xml")){
                        result.value = MimeType.XML.description();
                    }else{
                        throw new IllegalArgumentException("Unsupported response content type: " + tmpValue);
                    }
                    break;
                }
            }

            return result;
        }

        return null;
    }

    /**
     * Evaluate the standard condition against the request or response
     * For example: host = 'example.com'
     */
    private boolean evaluateStandardCondition(Condition condition, ProxyHttpRequestResponse proxyRequestOrResponse) {
        if (!fieldExtractors.containsKey(condition.key)) {
            return false;
        }

        Object fieldValue = fieldExtractors.get(condition.key).apply(proxyRequestOrResponse);
        if (fieldValue == null) {
            return false;
        }

        return isComparedValues(condition.operator, fieldValue.toString(), condition.value);
    }

    /**
     * Evaluate the length condition against the request or response
     * For example: len(body) > 10
     */
    private boolean evaluateLengthCondition(Condition condition, ProxyHttpRequestResponse request) {
        if (!fieldExtractors.containsKey(condition.key)) {
            return false;
        }

        Object fieldValue = fieldExtractors.get(condition.key).apply(request);
        if (fieldValue == null) {
            return false;
        }

        try {
            int length = fieldValue.toString().length();
            int intValue = Integer.parseInt((String)condition.value);
            return compareNumbers(condition.operator, length, intValue);
        } catch (NumberFormatException e) {
            return false;
        }
    }



    /**
     * Compare two string values based on the operator
     * This function is used for standard conditions like: host = 'example.com'
     */
    private boolean isComparedValues(String operator, String fieldValue, Object conditionValue) {
        switch (operator) {
            case "=":
                return fieldValue.equals(conditionValue);
            case "!=":
                return !fieldValue.equals(conditionValue);
            case "like":
                return fieldValue.contains((String)conditionValue);
            case ">":
                return fieldValue.compareTo((String)conditionValue) > 0;
            case "<":
                return fieldValue.compareTo((String)conditionValue) < 0;
            default:
                return false;
        }
    }


    /**
     * Compare two numbers based on the operator,
     * This function is used for length check when condition is like: len(body) > 10
     */
    private boolean compareNumbers(String operator, int actual, int expected) {
        switch (operator) {
            case ">":
                return actual > expected;
            case "<":
                return actual < expected;
            case ">=":
                return actual >= expected;
            case "<=":
                return actual <= expected;
            case "=":
                return actual == expected;
            case "!=":
                return actual != expected;
            default:
                return false;
        }
    }
}
