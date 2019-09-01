package com.johnturkson.messaging_server;

import java.nio.ByteBuffer;

public interface ServerEventListener {
    void onText(Server server, String authentication, CharSequence text, boolean last);
    
    void onBinary(Server server, String authentication, ByteBuffer binary, boolean last);
}
