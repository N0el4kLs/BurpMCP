package com.noel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.*;
import burp.api.montoya.proxy.*;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;
import com.noel.utils.SQLParser;

import static burp.api.montoya.intruder.PayloadProcessingResult.usePayload;

import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Handers {

    private MontoyaApi api;

    Handers(MontoyaApi api) {
        this.api = api;
    }

    public List<ProxyHttpRequestResponse> GetHistory() {
        return this.api.proxy().
                history(proxyHttpRequestResponse -> proxyHttpRequestResponse.request().path().contains(".php"));
    }

    public List<ProxyHttpRequestResponse> QueryHistory(ReqJson reqJson) {
        int limit = reqJson.getLimit();
        List<Map<String, String>> conditions = reqJson.getConditions();

        List<ProxyHttpRequestResponse> filteredHistory = this.api.proxy().history(request -> {
            // If no conditions are provided, return all requests
            if (conditions == null || conditions.isEmpty()) {
                return true;
            }

            // Check if ANY of the condition sets match (OR logic between condition sets)
            for (java.util.Map<String, String> conditionSet : conditions) {
                boolean setMatches = true;

                // For each condition set, ALL conditions must match (AND logic within a set)

                String location = conditionSet.get("location");
                String condition = conditionSet.get("condition");

                if (condition == null || condition.isEmpty()) {
                    continue; // Skip empty conditions
                }

                switch (location) {
                    case "req":
                        setMatches = setMatches && request.request().toString().contains(condition);
                        break;
                    case "resp":
                        setMatches = setMatches && request.response().toString().contains(condition);
                        break;
                    case "url":
                        setMatches = setMatches && request.request().url().contains(condition);
                        break;
                    case "path":
                        setMatches = setMatches && request.request().path().contains(condition);
                        break;
                    case "body":
                        setMatches = setMatches && request.request().bodyToString().contains(condition);
                        break;
                    default:
                        // Unknown location filter
                        break;
                }

                // If any condition in this set fails, no need to check others
                if (!setMatches) {
                    break;
                }


                // If any condition set matches completely, return true
                if (setMatches) {
                    return true;
                }
            }

            // No condition sets matched
            return false;
        });


        // Apply limit if needed
        if (limit > 0 && filteredHistory.size() > limit) {
            return filteredHistory.subList(0, limit);
        }

        return filteredHistory;
    }



    /**
     * 使用SQL风格的语法查询Burpsuite代理历史记录
     * 支持格式: select field1,field2 from proxy where condition1 and condition2 limit N
     * 例如: select host,path,method from proxy where path like '/api' and method='POST' limit 10
     *
     * @param sql SQL风格的查询语句
     * @return 查询结果列表
     */
    public List<Map<String, Object>> QueryHistoryBySQL(String sql) {
        try {
            // Parse the SQL style query
            SQLParser parser = new SQLParser(sql, this.api);

            // 获取查询结果
            List<ProxyHttpRequestResponse> filteredHistory = parser.executeQuery();

            List<Map<String, Object>> rst = parser.processSelectedFields(filteredHistory, parser.getSelectFields());


            // 记录查询日志
            api.logging().logToOutput("SQL查询成功，返回 " + rst.size() + " 条结果");

            return rst;
        } catch (Exception e) {
            throw new RuntimeException("SQL查询执行失败: " + e.getMessage());
        }
    }

}
