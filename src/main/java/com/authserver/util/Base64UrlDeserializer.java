package com.authserver.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.deser.std.StringDeserializer;

import java.io.IOException;

public class Base64UrlDeserializer extends JsonDeserializer<String> {

    private static final StringDeserializer STRING_DESERIALIZER = new StringDeserializer();

    @Override
    public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        try {
            // First try to use the standard StringDeserializer
            return STRING_DESERIALIZER.deserialize(p, ctxt);
        } catch (Exception e) {
            // If that fails, try a more robust approach
            if (p.getCurrentToken() == JsonToken.VALUE_STRING) {
                // Get the raw bytes from the parser
                byte[] bytes = p.getBinaryValue();
                // Convert to string, ignoring invalid UTF-8 sequences
                return new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
            }
            // If all else fails, return an empty string rather than throwing an exception
            return "";
        }
    }
}