By enabling HTTP/1.1 on the server side and making the request with the client in HTTP/1.1, I encounter the error, and enabling snimapping I observe the erro:

```
java.lang.NullPointerException: Cannot invoke "io.netty.handler.ssl.SslHandler.handshakeFuture()" because the return value of "io.netty.channel.ChannelPipeline.get(java.lang.Class)" is null
at reactor.netty.channel.MicrometerChannelMetricsHandler$TlsMetricsHandler.channelActive(MicrometerChannelMetricsHandler.java:275)
at io.netty.channel.AbstractChannelHandlerContext.invokeChannelActive(AbstractChannelHandlerContext.java:262)
at io.netty.channel.AbstractChannelHandlerContext.invokeChannelActive(AbstractChannelHandlerContext.java:238)
at io.netty.channel.AbstractChannelHandlerContext.fireChannelActive(AbstractChannelHandlerContext.java:231)
at io.netty.handler.ssl.AbstractSniHandler.channelActive(AbstractSniHandler.java:157)
at io.netty.channel.AbstractChannelHandlerContext.invokeChannelActive(AbstractChannelHandlerContext.java:260)
at io.netty.channel.AbstractChannelHandlerContext.invokeChannelActive(AbstractChannelHandlerContext.java:238)
at io.netty.channel.AbstractChannelHandlerContext.fireChannelActive(AbstractChannelHandlerContext.java:231)
at io.netty.channel.DefaultChannelPipeline$HeadContext.channelActive(DefaultChannelPipeline.java:1395)
at io.netty.channel.AbstractChannelHandlerContext.invokeChannelActive(AbstractChannelHandlerContext.java:258)
at io.netty.channel.AbstractChannelHandlerContext.invokeChannelActive(AbstractChannelHandlerContext.java:238)
at io.netty.channel.DefaultChannelPipeline.fireChannelActive(DefaultChannelPipeline.java:894)
at io.netty.channel.AbstractChannel$AbstractUnsafe.register0(AbstractChannel.java:521)
at io.netty.channel.AbstractChannel$AbstractUnsafe.access$200(AbstractChannel.java:428)
at io.netty.channel.AbstractChannel$AbstractUnsafe$1.run(AbstractChannel.java:485)
at io.netty.util.concurrent.AbstractEventExecutor.runTask(AbstractEventExecutor.java:173)
at io.netty.util.concurrent.AbstractEventExecutor.safeExecute(AbstractEventExecutor.java:166)
at io.netty.util.concurrent.SingleThreadEventExecutor.runAllTasks(SingleThreadEventExecutor.java:469)
at io.netty.channel.nio.NioEventLoop.run(NioEventLoop.java:569)
at io.netty.util.concurrent.SingleThreadEventExecutor$4.run(SingleThreadEventExecutor.java:994)
at io.netty.util.internal.ThreadExecutorMap$2.run(ThreadExecutorMap.java:74)
at io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30)
at java.base/java.lang.Thread.run(Thread.java:1583)
```

Disabling HTTP/1.1 and making the request only in H2, I encounter the following error (always with snimapping enabled):
```
ott 17, 2024 11:49:23 AM org.bouncycastle.jsse.provider.ProvTlsClient notifyConnectionClosed
INFORMAZIONI: [client #1 @3ecabaaf] disconnected from localhost:8443
Exception in thread "main" javax.net.ssl.SSLException: org.bouncycastle.tls.TlsFatalAlert: unexpected_message(10); Unsupported UNKNOWN(0)
at java.net.http/jdk.internal.net.http.HttpClientImpl.send(HttpClientImpl.java:960)
at java.net.http/jdk.internal.net.http.HttpClientFacade.send(HttpClientFacade.java:133)
at com.diennea.carapace.Main.main(Main.java:141)
Caused by: javax.net.ssl.SSLException: org.bouncycastle.tls.TlsFatalAlert: unexpected_message(10); Unsupported UNKNOWN(0)
at org.bouncycastle.jsse.provider.ProvSSLEngine.unwrap(Unknown Source)
at java.base/javax.net.ssl.SSLEngine.unwrap(SSLEngine.java:679)
at java.net.http/jdk.internal.net.http.common.SSLFlowDelegate$Reader.unwrapBuffer(SSLFlowDelegate.java:542)
at java.net.http/jdk.internal.net.http.common.SSLFlowDelegate$Reader.processData(SSLFlowDelegate.java:438)
at java.net.http/jdk.internal.net.http.common.SSLFlowDelegate$Reader$ReaderDownstreamPusher.run(SSLFlowDelegate.java:269)
at java.net.http/jdk.internal.net.http.common.SequentialScheduler$LockingRestartableTask.run(SequentialScheduler.java:182)
at java.net.http/jdk.internal.net.http.common.SequentialScheduler$CompleteRestartableTask.run(SequentialScheduler.java:149)
at java.net.http/jdk.internal.net.http.common.SequentialScheduler$SchedulableTask.run(SequentialScheduler.java:207)
at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)
at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642)
at java.base/java.lang.Thread.run(Thread.java:1583)
Caused by: org.bouncycastle.tls.TlsFatalAlert: unexpected_message(10); Unsupported UNKNOWN(0)
at org.bouncycastle.tls.RecordStream.checkRecordType(Unknown Source)
at org.bouncycastle.tls.RecordStream.previewRecordHeader(Unknown Source)
at org.bouncycastle.tls.TlsProtocol.safePreviewRecordHeader(Unknown Source)
at org.bouncycastle.tls.TlsProtocol.previewInputRecord(Unknown Source)
at org.bouncycastle.jsse.provider.ProvSSLEngine.getRecordPreview(Unknown Source)
... 11 more
```

Without snimapping, I do not encounter any error.
