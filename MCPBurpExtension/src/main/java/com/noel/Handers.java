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
     * 使用SQL风格的语法查询Burpsuite代理历史记录
     * 支持格式: select field1,field2 from proxy where condition1 and condition2 limit N
     * 例如: select host,path,method from proxy where path like '/api' and method='POST' limit 10
     *
     * @param sql SQL风格的查询语句
     * @return 查询结果列表
     */
//    public List<Map<String, Object>> QueryHistoryBySQL(String sql) {
//        try {
//            // Parse the SQL style query
//            SQLParser parser = new SQLParser(sql, this.api);
//
//            // 获取查询结果
//            List<ProxyHttpRequestResponse> filteredHistory = parser.executeQuery();
//
//            List<Map<String, Object>> rst = parser.processSelectedFields(filteredHistory, parser.getSelectFields());
//
//
//            // 记录查询日志
//            api.logging().logToOutput("SQL查询成功，返回 " + rst.size() + " 条结果");
//
//            return rst;
//        } catch (Exception e) {
//            throw new RuntimeException("SQL查询执行失败: " + e.getMessage());
//        }
//    }

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
