package com.noel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import org.jboss.com.sun.net.httpserver.HttpExchange;
import org.jboss.com.sun.net.httpserver.HttpServer;


import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class MCPExtension implements BurpExtension {

    private HttpServer server;
    private Logging logging;
    private  Handers handers;


    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return BurpExtension.super.enhancedCapabilities();
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        this.handers = new Handers(api);

        try{
            startServer();
        }catch (IOException e){
            this.logging.logToError("[Error] Can not start the server", e);
        }


        Extension extension = api.extension();
        extension.registerUnloadingHandler(new ExtensionUnloadHandler());
    }


    private void startServer() throws IOException {
        int defaultPort = 8889;


        // Each listing endpoint uses offset & limit from query params:
        try{
            this.server = HttpServer.create(new InetSocketAddress(defaultPort), 0);

            server.createContext("/", exchange -> {
                sendResponse(exchange, "Burpsuite HTTP server for MCP started!");
            });

            server.createContext("/allhistory", exchange -> {
                List<ProxyHttpRequestResponse> allhistory = this.handers.GetHistory();

                StringBuilder result = new StringBuilder();
                allhistory.forEach(item -> {
                    logging.logToOutput(item.request().toString());
                    result.append(item.request().toString()).append("\n");
                    result.append(item.response().toString()).append("\n");
                });

                sendResponse(exchange, result.toString());
            });


            server.createContext("/queryHistory", exchange->{
                ReqJson reqJson = parseJsonParams(exchange);
//                logging.logToOutput("[Info] Query history: "+reqJson.toString());
                List<ProxyHttpRequestResponse> history = this.handers.QueryHistory(reqJson);
                List<HashMap<String, String>> rst = new ArrayList<>();
                history.forEach(item -> {
                    HashMap<String, String> info = new HashMap<>();
                    info.put("req", item.request().toString());
                    info.put("resp", item.response().toString());
                    rst.add(info);
                });

                Gson gson = new Gson();
                String responseJson = null;

                try {
                    JsonResponse jsonResponse = new JsonResponse(200,"success", rst);
                    responseJson = gson.toJson(jsonResponse);
                } catch (Exception e) {
                    JsonResponse jsonResponse = new JsonResponse(500,"Server Error", e);
                    responseJson = gson.toJson(jsonResponse);
                    this.logging.logToError("Error processing or sending response", e);
                }finally {
                    sendResponse2(exchange, responseJson);
                }
            });

        }catch(IOException e){
            this.logging.logToError("[Error] Can't start server: " + e);
        }catch (Exception e){
            this.logging.logToOutput("[Error] Unknown error while starting server: " + e);
        }




        server.setExecutor(null);
        new Thread(() -> {
            server.start();
            this.logging.logToOutput("Start the BurpSite MCP HTTP on localhost:" + defaultPort);
        }, "BurpSuiteMCP-HTTP-Server")
                .start();
    }

    private void sendResponse(HttpExchange exchange,String response) throws IOException{
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendResponse2(HttpExchange exchange,String response) throws IOException{
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);

        OutputStream outStream = exchange.getResponseBody();
        outStream.write(bytes);
        outStream.close();
    }

    /**
     * Parse query parameters from the request URI
     * @param exchange HttpExchange object containing the request
     * @return Map of query parameters
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    result.put(kv[0], kv[1]);
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                params.put(kv[0], kv[1]);
            }
        }
        return params;
    }
    
    /**
     * Parse JSON data from POST request body
     * Handles complex JSON structures including nested objects and arrays
     */
    private ReqJson parseJsonParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Gson gson = new GsonBuilder().create();
        ReqJson reqJson = null;
        try {
            reqJson = gson.fromJson(bodyStr, ReqJson.class);
        } catch (Exception e) {
            logging.logToError("[Error] Error parsing JSON request body", e);
        }

        return reqJson;
    }


    /**
     * ExtensionUnloadHandler unload extension handler
     */
    private class ExtensionUnloadHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            logging.logToOutput("Unloading....");
            server.stop(0);
            logging.logToOutput("Done unloading!");
        }
    }
}
