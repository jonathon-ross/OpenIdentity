package org.openidentity.samples;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class ProtectedResourceController {
 @GetMapping("/api/records")
 String records(){return "records";}
}
