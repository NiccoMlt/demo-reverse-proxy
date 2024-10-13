package com.diennea.carapace;

import io.netty.handler.logging.LogLevel;
import java.util.function.Function;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.server.HttpServer;
import reactor.netty.transport.logging.AdvancedByteBufFormat;
import reactor.tools.agent.ReactorDebugAgent;

public class Main {

    private static final String HOST = "localhost";
    private static final int PORT = 8080;

    static {
        ReactorDebugAgent.init();
    }

    public static void main(final String... args) {
        final HttpServer httpServer = HttpServer
                .create()
                .host(HOST)
                .port(PORT)
                .protocol(HttpProtocol.H2C)
                .metrics(true, Function.identity())
                .wiretap(HttpServer.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.HEX_DUMP)
                .handle((request, response) -> response.sendString(Mono.just("Hello from server")));
        final DisposableServer server = httpServer.bindNow();

        final HttpClient client = HttpClient
                .create()
                .host(HOST)
                .port(PORT)
                .protocol(HttpProtocol.H2C)
                .metrics(true, Function.identity())
                .wiretap(HttpClient.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.HEX_DUMP);

        client.get()
                .response()
                .doFinally(signalType -> server.disposeNow())
                .block();
    }
}