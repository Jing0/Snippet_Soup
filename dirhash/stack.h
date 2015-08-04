/*
 * A simple generic stack implementation in c
 *
 * The definition of the stack and it's methods
 *
 * File:   stack.h
 * Author: Jackie Kuo <j.kuo2012@gmail.com>
 *
 * @license GNU AGPLv3
 */

#ifndef _STACK_H
#define _STACK_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct sta_t{
    int allocatedSize;
    int size;
    int elemSize;
    void *elements;
} sta_t;

/*
 * The "Constructor" allocates a new stack
 */
void stack_new(sta_t *s, int elemSize);

/*
 * The "Destructor" deallocates a allocated stack
 */
void stack_destroy(sta_t *s);

/*
 * Used to add a value to the stack
 * Requires the data that valueAddress is of the same size as elemSize that was passed to stack_new
 * otherwise funky stuff will happen.
 * If you give the stack_new function sizeof(int) valueAddress should point to an int.
 */
void stack_push(sta_t *s, void *valueAddress);

/*
 * Used to retrive a value from the stack and removing it
 * The data at returnAddress is populated by the data at the top of the stack
 *
 * Requires the data that valueAddress is of the same size as elemSize that was passed to stack_new
 * otherwise funky stuff will happen.
 * If you give the stack_new function sizeof(int) valueAddress should point to an int.
 */
void stack_pop(sta_t *s, void *returnAddress);

/*
 * Used to retrive a value from the stack without removing it
 * The data at returnAddress is populated by the data at the top of the stack
 *
 * Requires the data that valueAddress is of the same size as elemSize that was passed to stack_new
 * otherwise funky stuff will happen.
 * If you give the stack_new function sizeof(int) valueAddress should point to an int.
 */
void stack_peek(sta_t *s, void *returnAddress);

#ifdef  __cplusplus
}
#endif

#endif  /* _STACK_H */