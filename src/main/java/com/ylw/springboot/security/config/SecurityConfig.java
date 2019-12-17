package com.ylw.springboot.security.config;

import com.ylw.springboot.security.entity.Permission;
import com.ylw.springboot.security.handler.MyAuthenticationFailureHandler;
import com.ylw.springboot.security.handler.MyAuthenticationSuccessHandler;
import com.ylw.springboot.security.mapper.PermissionMapper;
import com.ylw.springboot.security.security.MyUserDetailsService;
import com.ylw.springboot.security.utils.MD5Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

// Security 配置
@Component
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private MyAuthenticationFailureHandler failureHandler;
	@Autowired
	private MyAuthenticationSuccessHandler successHandler;
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	@Autowired
	private PermissionMapper permissionMapper;

	// 配置认证用户信息和权限
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// // 添加admin账号
		// auth.inMemoryAuthentication().withUser("admin").password("123456").
		// authorities("showOrder","addOrder","updateOrder","deleteOrder");
		// // 添加userAdd账号
		// auth.inMemoryAuthentication().withUser("userAdd").password("123456").authorities("showOrder","addOrder");
		// 如果想实现动态账号与数据库关联 在该地方改为查询数据库
		auth.userDetailsService(myUserDetailsService).passwordEncoder(new PasswordEncoder() {

			// 加密的密码与数据库密码进行比对CharSequence rawPassword 表单字段 encodedPassword
			// 数据库加密字段
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				System.out.println("rawPassword:" + rawPassword + ",encodedPassword:" + encodedPassword);
				// 返回true 表示认证成功 返回fasle 认证失败
				return MD5Util.encode((String) rawPassword).equals(encodedPassword);
			}

			// 对表单密码进行加密
			public String encode(CharSequence rawPassword) {
				System.out.println("rawPassword:" + rawPassword);
				return MD5Util.encode((String) rawPassword);
			}
		});
	}

	// 配置拦截请求资源
	protected void configure(HttpSecurity http) throws Exception {
		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests = http
				.authorizeRequests();
		// 1.读取数据库权限列表
		List<Permission> listPermission = permissionMapper.findAllPermission();
		for (Permission permission : listPermission) {
			// 设置权限
			authorizeRequests.antMatchers(permission.getUrl()).hasAnyAuthority(permission.getPermTag());
		}
		authorizeRequests.antMatchers("/login").permitAll().antMatchers("/**").fullyAuthenticated().and().formLogin()
				.loginPage("/login").successHandler(successHandler).and().csrf().disable();

	}

	@Bean
	public static NoOpPasswordEncoder passwordEncoder() {
		return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
	}

}
