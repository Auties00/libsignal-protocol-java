package com.github.auties00.libsignal.exception;

public final class SignalDuplicateMessageException
        extends SignalException {
    private final int chainIndex;
    private final int counter;

    public SignalDuplicateMessageException(int chainIndex, int counter) {
        super("Received message with old counter: " + chainIndex + " , " + counter);
        this.chainIndex = chainIndex;
        this.counter = counter;
    }

    public int chainIndex() {
        return chainIndex;
    }

    public int counter() {
        return counter;
    }
}
