package org.openidentity.samples;
import org.springframework.web.bind.annotation.*;
@RestController
final class ProtectedResourceController {
 @GetMapping("/api/records") String records(){return "records";}
 @GetMapping("/api/records/{id}") String record(@PathVariable("id") String id){return "record:"+id;}
 @DeleteMapping("/api/records/{id}") String delete(@PathVariable("id") String id){return "deleted:"+id;}
}