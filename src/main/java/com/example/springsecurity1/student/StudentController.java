package com.example.springsecurity1.student;

import java.util.Arrays;
import java.util.List;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> students = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2,"Maria Jones"),
            new Student(3,"Anna Smith"));

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return students.stream()
                .filter(student->studentId.equals(student.getStudentId()))
                .findFirst().orElseThrow(()->new IllegalStateException("student " +studentId+ " does not exist"));
    }
}
