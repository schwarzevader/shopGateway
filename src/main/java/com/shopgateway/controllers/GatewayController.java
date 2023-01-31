package com.shopgateway.controllers;


import com.shopgateway.domain.Customer;
import com.shopgateway.service.CustomerInfoService;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.Principal;

@RestController
public class GatewayController {

//    @Autowired
//    private WebClient.Builder webClient;

    @Autowired
    private CustomerInfoService customerInfoService;

    @GetMapping(value = "/")
    public String getStr(Principal principal) {
            return "Hello, " + principal.getName();
        }



    //@RolesAllowed({ "ADMIN", "USER" })
    @GetMapping("/mail")
    public ResponseEntity<String> getMail(Principal principal){
        return new ResponseEntity<String>(principal.getName(), HttpStatus.OK);
    }


//    @GetMapping("/user")
//    public String getMail(){
//        return customerInfoService.loginCustomer("").getMail();
//    }


}
