package com.shopgateway.service;

import com.shopgateway.domain.Customer;
import com.shopgateway.domain.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomerInfoService {


    @Autowired
    private BCryptPasswordEncoder passwordEncoder ;

//    @Autowired
//    private RestTemplate restTemplate ;
    //---
//    @Autowired
//    private  WebClient.Builder webClient;


//
//    public  Customer loadUserByUsername(String username){
//        if (webClient!=null){
//            System.out.println("webClient != null");
//        }
//        String url = "http://shop/cmp";
//        String url2 = "http://localhost:8180/cmp";
//        Customer customer = webClient.build()
//                .get()
//                .uri(url)
//                .retrieve()
//                .bodyToMono(Customer.class)
//                .block();
//        //return restTemplate.getForObject(url, Customer.class);
//        return customer;
//    }
//
//    public Mono<Customer> findByUN(String mail) {
//
//        String url = "http://shop/customers/cmp";
//        String url2 = "http://localhost:8180/customers/cmp";
//        Mono <Customer> customer = webClient.build()
//                .get()
//                .uri(url)
//                .retrieve()
//                .bodyToMono(Customer.class);
//        //        Customer customer = new Customer();
////        List<Role> roleList = new ArrayList<>();
////        Role role = new Role();
////        role.setId(1L);
////        role.setRole("User");
////        roleList.add(role);
////        customer.setMail("customer@gmail.com");
////        customer.setPassword(passwordEncoder.encode("123"));
////        customer.setRoleList(roleList);
//        return customer;
//    }
//
//
//
//    public Customer findByUsername(String mail){
////        if (webClient!=null){
////            System.out.println("webClient != null");
////        }
//        String url = "http://shop/cmp";
//        String url2 = "http://localhost:8180/cmp";
////        Customer customer = webClient.build()
////                .get()
////                .uri(url2)
////                .retrieve()
////                .bodyToMono(Customer.class)
////                .block();
////
////        Customer customer = restTemplate.getForObject(url,Customer.class);
////        System.out.println("customer in findByUsername---"+customer.toString());
//        return null;
//    }
//
//    public Customer loginCustomer(String mail){
//
//        String url = "http://shop/customers/log/";
//        String customerMail="valdis@gmail.com";
//        return webClient.build()
//                .get()
//                //.uri("http://shop/customers/log/{"+customerMail+"}")
//                .uri(url+customerMail)
//                .retrieve()
//                .bodyToMono(Customer.class)
//                .block();
//
////        return webClient.build()
////                .get()
////                .uri(uriBuilder -> uriBuilder.path(url).queryParam("mail",customerMail).build())
////                .retrieve()
////                .bodyToMono(Customer.class)
////                .block();
//
////        return WebClient.create("http://localhost:8180")
////                .get()
////                .uri(uriBuilder -> uriBuilder.path("/customers/login/")
////                        .queryParam("mail", customerMail)
////                        .build())
////                .retrieve()
////                .bodyToMono(Customer.class).block();
//    }

    //---
}
