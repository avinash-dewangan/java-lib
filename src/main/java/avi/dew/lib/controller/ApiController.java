package avi.dew.lib.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static avi.dew.lib.controller.CryptoService.decrypt;
import static avi.dew.lib.controller.CryptoService.decryptCryptoJs;

@CrossOrigin(origins = "*")
@RestController
public class ApiController {

//    @Autowired
//    private CryptoService cryptoService;

    @PostMapping("/api/data")
    public String processData(@RequestBody String encryptedData) {
        try {
            // Decrypt the received encrypted data
            String decryptedData = decryptCryptoJs(encryptedData);

            // Convert the decrypted JSON string to a Person object
            ObjectMapper objectMapper = new ObjectMapper();
            Person person = objectMapper.readValue(decryptedData, Person.class);

            // Process the Person object as needed
            System.out.println("Decrypted Person: " + person.getName() + ", " + person.getAge());

            // Perform any business logic or return a response

            return decryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            return "Error processing data";
        }
    }
}

