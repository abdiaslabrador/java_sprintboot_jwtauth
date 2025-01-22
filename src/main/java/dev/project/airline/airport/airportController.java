package dev.project.airline.airport;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class airportController {

    @GetMapping("/airport")
    public String getAirport() {
        return "List of Airports";
    }

    @GetMapping("/public")
    public String getPublic() {
        return "Public API";
    }

    @GetMapping("/private")
    public String getPrivate() {
        return "Private API";
    }
}
