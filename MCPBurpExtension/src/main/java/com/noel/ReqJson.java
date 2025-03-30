package com.noel;

import java.util.List;
import java.util.Map;

public class ReqJson {
    private List<Map<String, String>> conditions;
    private int limit;

    public ReqJson(List<Map<String, String>> conditions, int limit) {
        this.conditions = conditions;
        this.limit = limit;
    }

    public List<Map<String, String>> getConditions() {
        return conditions;
    }

    public void setConditions(List<Map<String, String>> conditions) {
        this.conditions = conditions;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }
}
