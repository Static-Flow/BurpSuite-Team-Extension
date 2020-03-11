package teamextension;

import com.google.gson.*;

import java.lang.reflect.Type;

public class RequestCommentSerializer implements JsonSerializer<RequestComment> {
    public JsonElement serialize(final RequestComment requestComment, final Type type,
                                 final JsonSerializationContext context) {
        JsonObject result = new JsonObject();
        result.add("comment", new JsonPrimitive(requestComment.getComment()));
        result.add("userWhoCommented", new JsonPrimitive(requestComment.getUserWhoCommented()));
        result.add("timeOfComment", new JsonPrimitive(requestComment.getTimeOfComment()));
        return result;
    }
}