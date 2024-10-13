package com.diennea.carapace;

import io.netty.handler.logging.LogLevel;
import java.net.URI;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;
import reactor.netty.DisposableServer;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.server.HttpServer;
import reactor.netty.tcp.SslProvider;
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
        httpServer.warmup().block();
        final DisposableServer server = httpServer.bindNow();

        final HttpClient client = HttpClient
                .create()
                .host(HOST)
                .port(PORT)
                .wiretap(HttpClient.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL);
        client.warmup().block();
        client.get().response().block();
        server.onDispose().block();
    }
}
