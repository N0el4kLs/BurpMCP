package com.noel.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class SQLParser {
    private String[] selectFields;
    private List<String> whereConditions;
    private int limit;
    private MontoyaApi api;

    private final HashMap<String, Function<ProxyHttpRequestResponse, Object>> fieldExtractors;

    private static class Condition {
        String key;
        String operator;
        String value;
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


    // Execute the SQL query and return the results
    // This is a dummy implementation, replace it with your actual SQL query execution logic

    /**
     * 使用SQL风格的语法查询代理历史记录
     * 支持格式: select field1,field2 from proxy where condition1 and condition2 limit N
     * 例如: select host,path,method from proxy where path like '/api' and method='POST' limit 10
     *
     * @return 查询结果列表
     */
    public List<ProxyHttpRequestResponse> executeQuery() {
        List<ProxyHttpRequestResponse> filteredHistory = filterHistoryByConditions(this.getWhereConditions());
        if (this.getLimit() > 0 && filteredHistory.size() > this.getLimit()) {
            filteredHistory = filteredHistory.subList(0, this.getLimit());
        }

        return filteredHistory;
        // 处理选定的字段
//        return processSelectedFields(filteredHistory, this.getSelectFields());
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
        System.out.println("Parsed SQL query:");
        System.out.println("Select fields: " + String.join(", ", selectFields));
        System.out.println("Where conditions: " + String.join(", ", whereConditions));
        System.out.println("Limit: " + limit);
    }


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


    private static final Pattern LEN_PATTERN = Pattern.compile("len\\(([^)]+)\\)\\s*(>|<|>=|<=|!=|=)\\s*(\\d+)");
    private static final Pattern CONDITION_PATTERN = Pattern.compile("((?:req|resp)?(?:\\.|\\w+\\.)?\\w+)\\s*(=|like|!=|>=|<=|>|<)\\s*(?:'([^']*)'|\"([^\"]*)\"|([^\\s]+))");

    private Condition parseCondition(String condition) {
        Condition result = new Condition();

        // Handle length conditions
        Matcher lenMatcher = LEN_PATTERN.matcher(condition);
        if (lenMatcher.find()) {
            result.isLengthCheck = true;
            result.key = lenMatcher.group(1).trim().toLowerCase();
            result.operator = lenMatcher.group(2).trim();
            result.value = lenMatcher.group(3).trim();
            return result;
        }

        // Handle standard conditions
        Matcher condMatcher = CONDITION_PATTERN.matcher(condition);
        if (condMatcher.find()) {
            result.isLengthCheck = false;
            result.key = condMatcher.group(1).trim().toLowerCase();
            result.operator = condMatcher.group(2).trim();

            // Handle quoted values (single or double quotes) or unquoted values
            result.value = condMatcher.group(3) != null ? condMatcher.group(3) :
                    condMatcher.group(4) != null ? condMatcher.group(4) :
                            condMatcher.group(5);
            return result;
        }

        return null;
    }

    private boolean evaluateStandardCondition(Condition condition, ProxyHttpRequestResponse proxyRequestOrResponse) {
        if (!fieldExtractors.containsKey(condition.key)) {
            return false;
        }

        Object fieldValue = fieldExtractors.get(condition.key).apply(proxyRequestOrResponse);
        if (fieldValue == null) {
            return false;
        }

        return compareValues(condition.operator, fieldValue.toString(), condition.value);
    }

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
            int intValue = Integer.parseInt(condition.value);
            return compareNumbers(condition.operator, length, intValue);
        } catch (NumberFormatException e) {
            return false;
        }
    }

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

    private boolean compareValues(String operator, String fieldValue, String conditionValue) {
        switch (operator) {
            case "=":
                return fieldValue.equals(conditionValue);
            case "!=":
                return !fieldValue.equals(conditionValue);
            case "like":
                return fieldValue.contains(conditionValue);
            case ">":
                return fieldValue.compareTo(conditionValue) > 0;
            case "<":
                return fieldValue.compareTo(conditionValue) < 0;
            default:
                return false;
        }
    }

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
