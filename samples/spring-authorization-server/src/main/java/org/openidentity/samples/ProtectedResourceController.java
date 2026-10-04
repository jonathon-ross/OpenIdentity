package org.openidentity.samples;
import org.springframework.web.bind.annotation.*;
@RestController
final class ProtectedResourceController {
 @GetMapping("/api/records") String records(){return "records";}
 @GetMapping("/api/records/{id}") String record(@PathVariable String id){return "record:"+id;}
 @DeleteMapping("/api/records/{id}") String delete(@PathVariable String id){return "deleted:"+id;}
}