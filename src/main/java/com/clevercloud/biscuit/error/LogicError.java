package com.clevercloud.biscuit.error;

import java.util.List;
import java.util.Objects;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import io.vavr.control.Option;

public class LogicError {
    public Option<List<FailedCheck>> failed_checks() {
        return Option.none();
    }
    public JsonElement toJson() {
        return new JsonObject();
    }

    private static JsonElement jsonWrapper(JsonElement e) {
        JsonObject root = new JsonObject();
        root.add("FailedLogic", e);
        return root;
    }

    public static class InvalidAuthorityFact extends LogicError {
        final public String e;

        public InvalidAuthorityFact(String e) {
            this.e = e;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            InvalidAuthorityFact other = (InvalidAuthorityFact) o;
            return e.equals(other.e);
        }

        @Override
        public int hashCode() {
            return Objects.hash(e);
        }

        @Override
        public String toString() {
            return "LogicError.InvalidAuthorityFact{ error: "+ e + " }";
        }

        @Override
        public JsonElement toJson() {
            return LogicError.jsonWrapper(new JsonPrimitive("InvalidAuthorityFact"));
        }

    }

    public static class InvalidAmbientFact extends LogicError {
        final public String e;

        public InvalidAmbientFact(String e) {
            this.e = e;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            InvalidAmbientFact other = (InvalidAmbientFact) o;
            return e.equals(other.e);
        }

        @Override
        public int hashCode() {
            return Objects.hash(e);
        }

        @Override
        public String toString() {
            return "LogicError.InvalidAmbientFact{ error: "+ e + " }";
        }

        @Override
        public JsonElement toJson() {
            JsonObject child = new JsonObject();
            child.addProperty("error", this.e);
            JsonObject root = new JsonObject();
            root.add("InvalidAmbientFact", child);
            return LogicError.jsonWrapper(root);
        }
    }

    public static class InvalidBlockFact extends LogicError {
        final public long id;
        final public String e;

        public InvalidBlockFact(long id, String e) {
            this.id = id;
            this.e = e;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            InvalidBlockFact other = (InvalidBlockFact) o;
            return id == other.id && e.equals(other.e);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, e);
        }

        @Override
        public String toString() {
            return "LogicError.InvalidBlockFact{ id: "+id+", error: "+  e + " }";
        }

        @Override
        public JsonElement toJson() {
            JsonObject child = new JsonObject();
            child.addProperty("id",this.id);
            child.addProperty("error", this.e);
            JsonObject root = new JsonObject();
            root.add("InvalidBlockFact", child);
            return LogicError.jsonWrapper(root);
        }


    }
    public static class FailedChecks extends LogicError {
        final public List<FailedCheck> errors;

        public FailedChecks(List<FailedCheck> errors) {
            this.errors = errors;
        }

        public Option<List<FailedCheck>> failed_checks() {
            return Option.some(errors);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FailedChecks other = (FailedChecks) o;
            if(errors.size() != other.errors.size()) {
                return false;
            }
            for(int i = 0; i < errors.size(); i++) {
                if(!errors.get(i).equals(other.errors.get(i))) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public int hashCode() {
            return Objects.hash(errors);
        }

        @Override
        public String toString() {
            return "FailedChecks(" + errors +")";
        }
    }

    public static class NoMatchingPolicy extends LogicError {
        public NoMatchingPolicy() {
        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return super.equals(obj);
        }

        @Override
        public String toString() {
            return "NoMatchingPolicy{}";
        }
    }

    public static class Denied extends LogicError {
        private long id;

        public Denied(long id) {
            this.id = id;
        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return super.equals(obj);
        }

        @Override
        public String toString() {
            return "Denied("+id+")";
        }
    }

    public static class AuthorizerNotEmpty extends LogicError {

        public AuthorizerNotEmpty() {

        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return super.equals(obj);
        }

        @Override
        public String toString() {
            return "AuthorizerNotEmpty";
        }
    }
}