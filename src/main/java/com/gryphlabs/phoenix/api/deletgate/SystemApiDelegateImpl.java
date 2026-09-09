package com.gryphlabs.phoenix.api.deletgate;

import com.gryphlabs.phoenix.api.generated.api.SystemApiDelegate;
import com.gryphlabs.phoenix.api.generated.model.StatusResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SystemApiDelegateImpl implements SystemApiDelegate {
    @Value("${app.version}")
    private String version;

    @Override
    public ResponseEntity<StatusResponse> getApiStatus() {
        var response = new StatusResponse();
        response.setStatus("Success");
        response.setVersion(version);
        return ResponseEntity.ok(response);
    }
}
