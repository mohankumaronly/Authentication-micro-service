package com.rockrager.authentication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.rockrager.authentication.service.RedisService;

@RestController
@RequestMapping("/api/test-redis")
public class RedisTestController {

    @Autowired
    private RedisService redisService;

    @PostMapping("/save")
    public String saveToRedis(@RequestParam String key, @RequestParam String value) {
        redisService.save(key, value, 10);
        return "Saved: " + key + " = " + value;
    }

    @GetMapping("/get")
    public Object getFromRedis(@RequestParam String key) {
        return redisService.get(key);
    }

    @DeleteMapping("/delete")
    public String deleteFromRedis(@RequestParam String key) {
        redisService.delete(key);
        return "Deleted: " + key;
    }
}