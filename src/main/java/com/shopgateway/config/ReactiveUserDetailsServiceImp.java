package com.shopgateway.config;

import com.shopgateway.domain.Customer;
import com.shopgateway.service.CustomerInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;

//import static sun.java2d.loops.SurfaceType.Custom;


//@Component
public class ReactiveUserDetailsServiceImp {//implements ReactiveUserDetailsService {

    @Autowired
    private CustomerInfoService userRepository;
//-----
//    @Override
//    public Mono<UserDetails> findByUsername(String username) {
//        Mono<Customer> data = userRepository.findByUN(username);
//        return data.cast(UserDetails.class);
//        //return null;
//    }
//-----
//    @Override
//    public Mono<UserDetails> findByUsername(String username) {
//
//        return userRepository.findByUsername(username).switchIfEmpty(Mono.defer(() -> {
//            return Mono.error(new UsernameNotFoundException("User Not Found"));
//
//        })).map(Customer::toUserDetails);
//    }

//    @Override
//    public Mono<UserDetails> findByUsername(String username) {
////        Mono<Customer> data =  userRepository.findByUsername(username);
////        return data.cast(UserDetails.class);
//        //return userRepository.findByUsername(username);
//        Customer customer = userRepository.findByUsername(username);
//        if (customer==null){
//            throw new UsernameNotFoundException("Такого пользователя нет == " + username);
//        }else {
//            System.out.println("customer is found  -  " + customer.toString());
//        }
//
////        Role role = customer.getRole();
////        SimpleGrantedAuthority authorities = new SimpleGrantedAuthority(role.getRole());
//
//        Collection<SimpleGrantedAuthority> authorities =  new ArrayList<>();
//        customer.getRoleList().forEach(role -> {
//            authorities.add(new SimpleGrantedAuthority(role.getRole()));
//        });
//        return new org.springframework.security.core.userdetails.User(customer.getMail() ,customer.getPassword() , authorities);
//    }
}
