package com.shopgateway.domain;

import io.netty.util.AsyncMapping;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Customer implements Serializable {//implements UserDetails , Serializable { //extends Mono<UserDetails>
    private String mail;
    private String password;

//    private List<Role> roleList = new ArrayList<>();
//
//    public void setRole(Role role){
//        this.roleList.add(role);
//    }
//    public void setRoleList(List<Role> roleList) {
//        this.roleList = roleList;
//    }
//
//    public List<Role> getRoleList() {
//        return roleList;
//    }


    public void setMail(String mail) {
        this.mail = mail;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMail() {
        return mail;
    }

//    @Override
//    public String getPassword() {
//        return password;
//    }
//
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return null;
//    }
//
//    @Override
//    public String getUsername() {
//        return getMail();
//    }
//
//    @Override
//    public boolean isAccountNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        return true;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        return true;
//    }

//    public UserDetails toUserDetails() {
//        Collection<SimpleGrantedAuthority> authorities =  new ArrayList<>();
////        this.getRoleList().forEach(role -> {
////            authorities.add(new SimpleGrantedAuthority(role.getRole()));
////        });
//        return new org.springframework.security.core.userdetails.User(this.getMail() ,this.getPassword() , authorities);
//    }

//        public UserDetails toUserDetails() {
//            return User.withUsername(this.getMail())
//                    .password(this.getPassword())
//                    //.roles(roleList.toArray(String[]::new)) // Java 11 Collection to array
//                    .build();
//        }


}
