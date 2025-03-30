package com.noel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.*;
import burp.api.montoya.proxy.*;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;

import static burp.api.montoya.intruder.PayloadProcessingResult.usePayload;

import java.util.List;
import java.util.Map;

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
}
