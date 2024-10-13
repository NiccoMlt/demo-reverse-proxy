package com.diennea.carapace;

import io.netty.handler.logging.LogLevel;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.server.HttpServer;
import reactor.netty.transport.logging.AdvancedByteBufFormat;

public class Main {

    private static final String HOST = "localhost";
    private static final int PORT = 8080;

    public static void main(final String... args) {
        final HttpServer httpServer = HttpServer
                .create()
                .host(HOST)
                .port(PORT)
                .wiretap(HttpServer.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL)
                .handle((request, response) -> response.sendString(Mono.just("Hello from server")));
        final DisposableServer server = httpServer.bindNow();

        final HttpClient client = HttpClient
                .create()
                .host(HOST)
                .port(PORT)
                .wiretap(HttpClient.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL);

        client.get()
                .response()
                .doFinally(signalType -> server.disposeNow())
                .block();
    }
}