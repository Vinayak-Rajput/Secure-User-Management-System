package com.hdfclife.capstoneone.exception;

public class DisallowedRequestOriginException extends RuntimeException {
    public DisallowedRequestOriginException(String message) {
        super(message);
    }
}
