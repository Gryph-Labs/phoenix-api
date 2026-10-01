package com.gryphlabs.phoenix.api.auth.mapper;

import com.gryphlabs.phoenix.api.generated.auth.model.MessageResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

@Component
public class MessageMapper {
    @NonNull
    public MessageResponse of(@NonNull String message) {
        var response = new MessageResponse();
        response.setMessage(message);
        return response;
    }
}
