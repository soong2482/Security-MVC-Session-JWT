package com.spring.SecurityMVC.ConfigInfo.MybatisConfig;

import lombok.RequiredArgsConstructor;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import javax.sql.DataSource;

@Configuration
@RequiredArgsConstructor
public class MybatisConfig {

    private final DataSource dataSource;

    @Bean("sqlSessionFactory")
    public SqlSessionFactory sqlSessionFactory() throws Exception {
        String configPath = "/mybatis-config.xml";
        String mapperPath = "/mappers/**/*Mapper.xml";

        SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
        sqlSessionFactoryBean.setDataSource(dataSource);
        sqlSessionFactoryBean.setConfigLocation(new ClassPathResource(configPath));
        sqlSessionFactoryBean.setMapperLocations(new PathMatchingResourcePatternResolver().getResources("classpath:" + mapperPath));
        return sqlSessionFactoryBean.getObject();

    }

    @Bean(destroyMethod = "clearCache")
    public SqlSessionTemplate sqlSessionTemplateMySql() throws Exception {
        return new SqlSessionTemplate(sqlSessionFactory());
    }
}