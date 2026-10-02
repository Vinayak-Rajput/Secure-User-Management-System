package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.entity.User;
import com.hdfclife.capstoneone.repository.UserRepository;
import com.hdfclife.capstoneone.exception.UserNotFoundException;
import com.hdfclife.capstoneone.exception.UserOperationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final TokenService tokenService;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUser(long id) {
        return userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Authenticated user no longer exists"));
    }

    @Transactional
    public String deleteUser(long id, String requesterUsername) {
        User user = getUser(id);

        if (user.getUsername().equals(requesterUsername)) {
            throw new UserOperationException("Administrators cannot delete their own account");
        }

        if ("ADMIN".equals(user.getRole())) {
            List<User> admins = userRepository.findAllByRoleForUpdate("ADMIN");
            if (admins.size() <= 1) {
                throw new UserOperationException("The last administrator account cannot be deleted");
            }
        }

        tokenService.revokeAllSessions(user.getUsername());
        userRepository.delete(user);
        return user.getUsername();
    }
}
