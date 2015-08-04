/*
 * A simple generic stack implementation in c
 *
 * The implementation of the stack's methods
 *
 * File:   stack.c
 * Author: Jackie Kuo <j.kuo2012@gmail.com>
 *
 * @license GNU AGPLv3
 */

#include <stdlib.h>
#include <string.h>

#include "stack.h"

void stack_new(sta_t *s, int elemSize) {
    s->allocatedSize = 16; // Default to a stack that is 16 elements high
    s->size = 0;
    s->elemSize = elemSize;
    s->elements = malloc(s->allocatedSize * s->elemSize); // Allocate the needed memory
}

void stack_destroy(sta_t *s) {
    free(s->elements); // Free the allocated memory
}

void stack_push(sta_t *s, void *valueAddress) {
    if (s->size == s->allocatedSize) {
        s->allocatedSize *= 2; // Use a doubling strategy. Every time the stack is too small, double it's size
        s->elements = realloc(s->elements, s->allocatedSize * s->elemSize); // Reallocate the memory to the new size
    }

    void *target = (char *) s->elements + s->size * s->elemSize; // Find the memory segment where to insert the new data
    memcpy(target, valueAddress, s->elemSize); // Copy the data from the valueAddress to target
    s->size += 1;
}

void stack_pop(sta_t *s, void *returnAddress) {
    if (s->size > 0) {
        s->size -= 1; // This "removes" the element, it will be overwritten the next time push is called
        void *source = (char *) s->elements + s->size * s->elemSize; // Find the memory segment where to fetch the data from
        memcpy(returnAddress, source, s->elemSize); // Copy the data to the returnAddress
    }
    // Else error!
}

void stack_peek(sta_t *s, void *returnAddress) {
    if (s->size > 0) {
        void *source = (char *) s->elements + (s->size - 1) * s->elemSize; // Find the memory segment where to fetch the data from
        memcpy(returnAddress, source, s->elemSize); // Copy the data to the returnAddress
    }
    // Else error!
}