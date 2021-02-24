package ku.message.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
<<<<<<< HEAD
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
=======
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
>>>>>>> 9db68f9d8f93b4c351602e541f1f324ad6b83aa1
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/home", "/css/**", "/js/**").permitAll()
                .anyRequest().authenticated()

<<<<<<< HEAD
                .and()
=======
        .and()
>>>>>>> 9db68f9d8f93b4c351602e541f1f324ad6b83aa1
                .exceptionHandling()
                .authenticationEntryPoint(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))

<<<<<<< HEAD
                .and()
                .oauth2Login()
                .defaultSuccessUrl("/home").permitAll()

                .and()
                .logout()
                .logoutSuccessUrl("/home").permitAll();
    }
=======
        .and()
                .oauth2Login()
                .defaultSuccessUrl("/home", true)

        .and()
                .logout()
                .logoutSuccessUrl("/home").permitAll();
    }

>>>>>>> 9db68f9d8f93b4c351602e541f1f324ad6b83aa1
}
