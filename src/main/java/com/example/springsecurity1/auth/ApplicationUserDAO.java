package com.example.springsecurity1.auth;

import java.util.Optional;


public interface ApplicationUserDAO {

     Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
