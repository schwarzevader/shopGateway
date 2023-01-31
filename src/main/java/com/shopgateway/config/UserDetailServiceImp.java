package com.shopgateway.config;

import com.shopgateway.domain.Customer;
import com.shopgateway.service.CustomerInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

//@Service
public class UserDetailServiceImp {//implements UserDetailsService {

    @Autowired
    private CustomerInfoService customerInfoService;


//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        Customer customer = customerInfoService.findByUsername(username);
//        Collection<SimpleGrantedAuthority> authorities =  new ArrayList<>();
////        customer.getRoleList().forEach(role -> {
////            authorities.add(new SimpleGrantedAuthority(role.getRole()));
////        });
//        return new org.springframework.security.core.userdetails.User(customer.getMail() ,customer.getPassword() , authorities);
//    }
}
