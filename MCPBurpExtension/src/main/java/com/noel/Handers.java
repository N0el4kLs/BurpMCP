package com.noel;

import burp.api.montoya.MontoyaApi;
import com.noel.utils.SQLParser;

import java.util.*;

public class Handers {

    private MontoyaApi api;

    Handers(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Search burp suite proxy history using SQL style query
     */
    public List<Map<String, Object>> QueryHistoryBySQL(String sql) {
        try {
            SQLParser parser = new SQLParser(sql, this.api);
            List<Map<String, Object>> rst = parser.processSelectedFields(parser.filterHistoryBySQL(), parser.getSelectFields());
            api.logging().logToOutput("[Info ]SQL execute success, get records: " + rst.size());
            return rst;
        } catch (Exception e) {
            throw new RuntimeException("[Error] SQL execute error: " + e.getMessage());
        }
    }

}
