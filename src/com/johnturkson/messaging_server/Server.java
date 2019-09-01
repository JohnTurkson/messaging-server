package com.johnturkson.messaging_server;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Server {
    private ServerSocket serverSocket;
    private ServerEventListener serverEventListener;
    private Map<String, List<Socket>> users;
    private int running;
    
    public Server(int port) {
        try {
            this.serverSocket = new ServerSocket(port);
            this.running = 0;
            this.users = new HashMap<>();
            throw new MalformedURLException(null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
    
    private Server(ServerSocket serverSocket, ServerEventListener serverEventListener) {
        this.serverSocket = serverSocket;
        this.serverEventListener = serverEventListener;
        this.users = new HashMap<>();
        this.running = 0;
    }
    
    public static Builder newBuilder() {
        return new Builder();
    }
    
    public ServerSocket getServerSocket() {
        return serverSocket;
    }
    
    public void start() {
        while (true) {
            try {
                // System.out.println("accepting...");
                Socket client = serverSocket.accept();
                // running++;
                awaitOpeningHandshake(client);
                // users.add(client); // done in acceptHandshake()
                CompletableFuture.runAsync(() -> {
                    while (!client.isClosed()) {
                        processRequest(client);
                    }
                    users.values().forEach(sockets -> sockets.remove(client));
                    users.keySet().removeIf(key -> users.get(key).isEmpty());
                });
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public void stop() {
        // this.running--;
    }
    
    public void awaitOpeningHandshake(Socket client) throws IOException {
        List<Pattern> headers = new ArrayList<>();
        headers.add(Pattern.compile("GET .+ HTTP/1.1"));
        headers.add(Pattern.compile("Connection: Upgrade"));
        // headers.add(Pattern.compile("Content-Length: \\d+"));
        headers.add(Pattern.compile("Host: .+"));
        headers.add(Pattern.compile("Upgrade: websocket"));
        headers.add(Pattern.compile("User-Agent: .+"));
        headers.add(Pattern.compile("Authorization: Basic (?<authorization>[A-Za-z0-9+/]+=?=?)"));
        headers.add(Pattern.compile("Sec-WebSocket-Key: (?<key>[A-Za-z0-9+/]+=?=?)"));
        headers.add(Pattern.compile("Sec-WebSocket-Version: 13"));
        
        InputStream in = client.getInputStream();
        StringBuilder handshake = new StringBuilder();
        byte delimiter = '\n';
        // TODO revert to old code
        try {
            while (!handshake.toString().endsWith("\r\n\r\n")) {
                byte b = (byte) in.read();
                handshake.append(Character.toString(b));
                System.out.println(b + " ");
                // System.out.print(Character.toString(b));
                // System.out.println(in.available());
                if (handshake.toString().endsWith("\n")) {
                    System.out.println(handshake);
                    System.out.println("-----");
                }
                System.out.println("in loop");
                if (handshake.toString().endsWith("\n\n")) {
                    System.out.println("nn");
                    break;
                }
            }
            System.out.println("out of loop");
            /*
                if (headers.stream().allMatch(p -> p.matcher(handshake).find())) {
                    break;
                }
             */
            
        } catch (IllegalArgumentException e) {
            System.out.println("failed:");
            System.out.println(handshake.toString());
            System.out.println("===");
            System.out.println("available: " + in.available());
            // unparsable character (0xFFFFFFFF) due to stream closing
            failHandshake(client);
        }
        
        System.out.println(handshake);
        
        Matcher authenticationMatcher = Pattern.compile("Authorization: Basic (?<authorization>[A-Za-z0-9+/]+=?=?)").matcher(handshake);
        
        if (authenticationMatcher.find()) {
            String decoded = "";
            for (byte authentication : Base64.getDecoder().decode(authenticationMatcher.group("authorization").getBytes())) {
                decoded += (char) authentication;
            }
            String username = decoded.split(":")[0];
            String password = decoded.split(":")[1];
            
            System.out.println("username: " + username);
            users.computeIfAbsent(username, k -> new ArrayList<>()).add(client);
            System.out.println("added");
        } else {
            System.out.println("cannot find key");
            failHandshake(client);
        }
        
        if (headers.stream().allMatch(p -> p.matcher(handshake).find())) {
            // flush rest of buffer
            // while (in.available() > 0) {
            //     int dumped = in.read();
            // }
            System.out.println("all match");
            acceptHandshake(client, handshake.toString());
            System.out.println("Handshake accepted.");
        } else {
            failHandshake(client);
        }
        
    }
    
    public void acceptHandshake(Socket client, String handshake) {
        // System.out.println("accepted");
        Matcher keyMatcher = Pattern.compile("Sec-WebSocket-Key: (?<key>.*)").matcher(handshake);
        if (keyMatcher.find()) {
            try {
                String responseString = "HTTP/1.1 101 Switching Protocols\r\n"
                        + "Connection: Upgrade\r\n"
                        + "Upgrade: websocket\r\n"
                        + "Sec-WebSocket-Accept: "
                        + Base64.getEncoder()
                        .encodeToString(MessageDigest.getInstance("SHA-1")
                                .digest((keyMatcher.group("key") +
                                        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                                        .getBytes()))
                        + "\r\n\r\n";
                byte[] responseBytes = responseString.getBytes();
                client.getOutputStream().write(responseBytes, 0, responseBytes.length);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public void failHandshake(Socket client) {
        System.out.println("failed handshake");
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        stop();
    }
    
    public void failConnection(Socket client) {
        System.out.println("failed connection");
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        stop();
    }
    
    public void processRequest(Socket client, List<Integer> previousPayload, int initialOpCode, int previousOpCode) {
        try {
            InputStream in = client.getInputStream();
            int first = in.read();
            boolean fin = first >>> 7 == 1;
            boolean rsv1 = first >>> 6 == 1;
            boolean rsv2 = first >>> 5 == 1;
            boolean rsv3 = first >>> 4 == 1;
            byte opcode = (byte) (first & 0xF);
            
            if (initialOpCode == 0) {
                initialOpCode = opcode;
            }
            
            int second = in.read();
            boolean mask = second >>> 7 == 1;
            long length = second & 0x7F;
            if (length == 126) {
                length = in.read() << 8 + in.read();
            } else if (length == 127) {
                closeConnection(client, List.of(3, -15)); // status 1009 - Message too big
                // TODO: unsupported, for now
                // length = in.read() << 56 + in.read() << 48 + in.read() << 40 + in.read() << 32 +
                //         in.read() << 24 + in.read() << 16 + in.read() << 8 + in.read();
            }
            
            byte[] maskingKey = new byte[4];
            if (mask) {
                for (int i = 0; i < 4; i++) {
                    maskingKey[i] = (byte) in.read();
                }
            }
            
            List<Integer> currentPayload = new ArrayList<>();
            for (long i = 0; i < length; i++) {
                currentPayload.add((byte) in.read() ^ maskingKey[(byte) (i & 3)]);
            }
            
            List<Integer> combinedPayload = new ArrayList<>();
            combinedPayload.addAll(previousPayload);
            combinedPayload.addAll(currentPayload);
            
            if (!mask) {
                failConnection(client);
            }
            
            // System.out.println("initial opcode: " + initialOpCode);
            // System.out.println("fin: " + fin);
            // System.out.println("opcode: " + opcode);
            
            // TODO redo
            if (opcode == 0) {
                if (initialOpCode == 0) {
                    failConnection(client);
                } else if (fin && initialOpCode == 1) {
                    processString(client, combinedPayload);
                } else if (fin && initialOpCode == 2) {
                    processBinary(client, combinedPayload);
                } else if (initialOpCode == 9) {
                    // Can't have ping continuation
                    failConnection(client);
                } else if (initialOpCode == 10) {
                    // Can't have pong continuation? (verify)
                    failConnection(client);
                } else {
                    processRequest(client, combinedPayload, initialOpCode, opcode);
                }
            } else if (opcode == 1) {
                if (fin) {
                    processString(client, combinedPayload);
                } else {
                    processRequest(client, combinedPayload, initialOpCode, opcode);
                }
            } else if (opcode == 2) {
                if (fin) {
                    processBinary(client, combinedPayload);
                } else {
                    processRequest(client, combinedPayload, initialOpCode, opcode);
                }
            } else if (opcode == 8) {
                if (fin) {
                    closeConnection(client, currentPayload);
                } else {
                    failConnection(client);
                }
            } else if (opcode == 9) {
                if (length > 125 || !fin) {
                    failConnection(client);
                } else {
                    processPing(client, combinedPayload);
                }
            } else if (opcode == 10) {
                if (length > 125 || !fin) {
                    failConnection(client);
                } else {
                    processPong(client, combinedPayload);
                }
            } else {
                failConnection(client);
            }
        } catch (IOException e) {
            failConnection(client);
        }
    }
    
    public void processRequest(Socket client) {
        processRequest(client, new ArrayList<>(), 0, 0);
    }
    
    private void processString(Socket client, List<Integer> payload) {
        String username = users.keySet()
                .stream()
                .filter(u -> users.get(u).contains(client))
                .findAny()
                .orElse("[Unknown]");
        String prefix = username + ": ";
        System.out.print(prefix);
        payload.forEach(p -> System.out.print((char) (int) p));
        System.out.println();
        
        byte[] header;
        int combinedSize = prefix.getBytes().length + payload.size();
        if (combinedSize < 126) {
            header = new byte[2];
            header[0] = -127;
            header[1] = (byte) combinedSize;
        } else if (combinedSize == 126) {
            header = new byte[4];
            header[0] = -127;
            header[1] = 126;
            header[2] = (byte) (combinedSize >>> 8);
            header[3] = (byte) combinedSize;
        } else {
            throw new UnsupportedOperationException();
        }
        
        byte[] message = new byte[payload.size()];
        for (int i = 0; i < payload.size(); i++) {
            message[i] = (byte) (int) payload.get(i);
        }
        
        serverEventListener.onText(this, username, new String(message), true);
        
        // TODO send message to recipient (if online)
        // users.keySet().forEach(u -> {
        //     try {
        //         u.getOutputStream().write(header, 0, header.length);
        //         // u.getOutputStream().write(key, 0, key.length);
        //         u.getOutputStream().write(prefix.getBytes(), 0, prefix.getBytes().length);
        //         u.getOutputStream().write(message, 0, message.length);
        //     } catch (IOException e) {
        //         e.printStackTrace();
        //     }
        // });
        
        
        // System.out.println("processing string...");
        // payload.forEach(i -> System.out.print((char) ((int) i)));
        // System.out.println();
        
        // if the server needs to return message after each string:
        // String responseMessage = "received";
        // byte[] responseBytes = new byte[responseMessage.length() + 2];
        // responseBytes[0] = -127;
        // responseBytes[1] = (byte) responseMessage.length();
        // for (int i = 0; i < responseMessage.length(); i++) {
        //     responseBytes[i + 2] = (byte) responseMessage.charAt(i);
        // }
        // try {
        //     client.getOutputStream().write(responseBytes, 0, responseBytes.length);
        // } catch (IOException e) {
        //     e.printStackTrace();
        // }
    }
    
    private void processBinary(Socket client, List<Integer> payload) {
        // payload.forEach(System.out::print);
        // System.out.println();
        
        
        // If unsupported, send 1003 back to sender and close the socket.
        try {
            // System.out.println("closed - 1003");
            byte[] response = {-120, 2, 3, -21}; // status 1003 - Unsupported
            client.getOutputStream().write(response, 0, response.length);
            stop();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // Sending a "received" response to sender:
        // String responseMessage = "received";
        // byte[] responseBytes = new byte[responseMessage.length() + 2];
        // responseBytes[0] = -127;
        // responseBytes[1] = (byte) responseMessage.length();
        // for (int i = 0; i < responseMessage.length(); i++) {
        //     responseBytes[i + 2] = (byte) responseMessage.charAt(i);
        // }
        // try {
        //     client.getOutputStream().write(responseBytes, 0, responseBytes.length);
        // } catch (IOException e) {
        //     e.printStackTrace();
        // }
    }
    
    public void closeConnection(Socket client, List<Integer> payload) {
        // System.out.println("closed");
        // int status = (payload.get(0) << 8) + (payload.get(1) & 0xff);
        // System.out.println("status: " + status);
        // for (int i = 2; i < payload.size(); i++) {
        //     System.out.print((char) (int) payload.get(i));
        // }
        // System.out.println();
        
        try {
            byte[] response = {-120, 2, (byte) (int) payload.get(0), (byte) (int) payload.get(1)};
            client.getOutputStream().write(response, 0, response.length);
            System.out.println("closed");
        } catch (IOException e) {
            e.printStackTrace();
        }
        stop();
    }
    
    private void processPing(Socket client, List<Integer> payload) {
        byte[] response = new byte[payload.size() + 2];
        response[0] = -118;
        response[1] = (byte) payload.size();
        
        for (int i = 0; i < payload.size(); i++) {
            response[i + 2] = (byte) (int) (payload.get(i));
        }
        
        try {
            client.getOutputStream().write(response, 0, response.length);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private void processPong(Socket client, List<Integer> payload) {
        // nothing needs to be done
    }
    
    public void sendText(String authentication, CharSequence text, boolean last) {
        // TODO REMOVE (testing only)
        users.values().forEach(sockets -> sockets.forEach(socket -> sendText(socket, text, last)));
        
        // TODO real code is this:
        // users.get(authentication).forEach(socket -> sendText(socket, text, last));
    }
    
    private void sendText(Socket client, CharSequence text, boolean last) {
        byte[] header;
        int messageSize = text.toString().getBytes().length;
        if (messageSize < 126) {
            header = new byte[2];
            header[0] = -127;
            header[1] = (byte) messageSize;
        } else if (messageSize == 126) {
            header = new byte[4];
            header[0] = -127;
            header[1] = 126;
            header[2] = (byte) (messageSize >>> 8);
            header[3] = (byte) messageSize;
        } else {
            throw new UnsupportedOperationException();
        }
        
        byte[] message = new byte[messageSize];
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) (int) text.charAt(i);
        }
        
        try {
            client.getOutputStream().write(header);
            client.getOutputStream().write(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void sendBinary(String authentication, ByteBuffer data, boolean last) {
        
    }
    
    public String generateMaskingKey() {
        int length = 4;
        String key = "";
        for (int i = 0; i < length; i++) {
            key += (char) ThreadLocalRandom.current().nextInt(1, 127);
        }
        return key;
    }
    
    public enum Response {
        NORMAL_CLOSURE(1000),
        GOING_AWAY(1001),
        PROTOCOL_ERROR(1002),
        UNSUPPORTED_DATA(1003),
        NO_STATUS_RECEIVED(1005),
        ABNORMAL_CLOSURE(1006),
        INVALID_FRAME_PAYLOAD_DATA(1007),
        POLICY_VIOLATION(1008),
        MESSAGE_TOO_BIG(1009),
        MANDATORY_EXTENSION(1010),
        INTERNAL_SERVER_ERROR(1011),
        TLS_HANDSHAKE(1015);
        
        private int status;
        
        Response(int status) {
            this.status = status;
        }
        
        public int getStatus() {
            return status;
        }
    }
    
    public enum ResponseType {
        TEXT,
        BINARY
    }
    
    public enum Opcode {
        CONTINUATION(0),
        TEXT(1),
        BINARY(2),
        CONNECTION_CLOSE(8),
        PING(9),
        PONG(10);
        
        private int code;
        
        Opcode(int code) {
            this.code = code;
        }
        
        public int getCode() {
            return code;
        }
    }
    
    public static class Builder {
        private ServerSocket serverSocket;
        private ServerEventListener serverEventListener;
        
        public Builder serverSocket(ServerSocket serverSocket) {
            this.serverSocket = serverSocket;
            return this;
        }
        
        public Builder serverEventListener(ServerEventListener serverEventListener) {
            this.serverEventListener = serverEventListener;
            return this;
        }
        
        public Server build() {
            return new Server(serverSocket, serverEventListener);
        }
    }
    
    public class MessageFrame {
        private boolean fin;
        private Opcode opcode;
        private boolean mask;
        private int length;
        private String maskingKey;
        private String payload;
        
        
    }
}
