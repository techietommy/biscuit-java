/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import io.vavr.control.Either;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import org.eclipse.biscuit.error.Error;

public abstract class Term implements Serializable {
  public abstract boolean match(Term other);

  public abstract Schema.TermV2 serialize();

  public static Either<Error.FormatError, Term> deserializeEnumV2(Schema.TermV2 term) {
    if (term.hasDate()) {
      return Date.deserializeV2(term);
    } else if (term.hasInteger()) {
      return Integer.deserializeV2(term);
    } else if (term.hasString()) {
      return Str.deserializeV2(term);
    } else if (term.hasBytes()) {
      return Bytes.deserializeV2(term);
    } else if (term.hasVariable()) {
      return Variable.deserializeV2(term);
    } else if (term.hasBool()) {
      return Bool.deserializeV2(term);
    } else if (term.hasSet()) {
      return Set.deserializeV2(term);
    } else {
      return Left(new Error.FormatError.DeserializationError("invalid Term kind: term.getKind()"));
    }
  }

  public abstract org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable);

  public static final class Date extends Term implements Serializable {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      } else {
        return this.equals(other);
      }
    }

    public Date(final long value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Date date = (Date) o;

      return value == date.value;
    }

    @Override
    public int hashCode() {
      return (int) (value ^ (value >>> 32));
    }

    @Override
    public String toString() {
      return "@" + this.value;
    }

    public Schema.TermV2 serialize() {
      return Schema.TermV2.newBuilder().setDate(this.value).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasDate()) {
        return Left(new Error.FormatError.DeserializationError("invalid Term kind, expected date"));
      } else {
        return Right(new Date(term.getDate()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Date(this.value);
    }
  }

  public static final class Integer extends Term implements Serializable {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Integer) {
        return this.value == ((Integer) other).value;
      }
      return false;
    }

    public Integer(final long value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Integer integer = (Integer) o;

      return value == integer.value;
    }

    @Override
    public int hashCode() {
      return (int) (value ^ (value >>> 32));
    }

    @Override
    public String toString() {
      return "" + this.value;
    }

    public Schema.TermV2 serialize() {
      return Schema.TermV2.newBuilder().setInteger(this.value).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasInteger()) {
        return Left(
            new Error.FormatError.DeserializationError("invalid Term kind, expected integer"));
      } else {
        return Right(new Integer(term.getInteger()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Integer(this.value);
    }
  }

  public static final class Bytes extends Term implements Serializable {
    private final byte[] value;

    public byte[] value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Bytes) {
        return this.value.equals(((Bytes) other).value);
      }
      return false;
    }

    public Bytes(final byte[] value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Bytes bytes = (Bytes) o;

      return Arrays.equals(value, bytes.value);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
      return this.value.toString();
    }

    public Schema.TermV2 serialize() {
      return Schema.TermV2.newBuilder().setBytes(ByteString.copyFrom(this.value)).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasBytes()) {
        return Left(
            new Error.FormatError.DeserializationError("invalid Term kind, expected byte array"));
      } else {
        return Right(new Bytes(term.getBytes().toByteArray()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Bytes(this.value);
    }
  }

  public static final class Str extends Term implements Serializable {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Str) {
        return this.value == ((Str) other).value;
      }
      return false;
    }

    public Str(final long value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Str s = (Str) o;

      return value == s.value;
    }

    @Override
    public int hashCode() {
      return (int) (value ^ (value >>> 32));
    }

    public Schema.TermV2 serialize() {
      return Schema.TermV2.newBuilder().setString(this.value).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasString()) {
        return Left(
            new Error.FormatError.DeserializationError("invalid Term kind, expected string"));
      } else {
        return Right(new Str(term.getString()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Str(
          symbolTable.formatSymbol((int) this.value));
    }
  }

  public static final class Variable extends Term implements Serializable {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      return true;
    }

    public Variable(final long value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Variable variable = (Variable) o;

      return value == variable.value;
    }

    @Override
    public int hashCode() {
      return (int) (value ^ (value >>> 32));
    }

    @Override
    public String toString() {
      return this.value + "?";
    }

    public Schema.TermV2 serialize() {
      return Schema.TermV2.newBuilder().setVariable((int) this.value).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasVariable()) {
        return Left(
            new Error.FormatError.DeserializationError("invalid Term kind, expected variable"));
      } else {
        return Right(new Variable(term.getVariable()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Variable(
          symbolTable.formatSymbol((int) this.value));
    }
  }

  public static final class Bool extends Term implements Serializable {
    private final boolean value;

    public boolean value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Bool) {
        return this.value == ((Bool) other).value;
      }
      return false;
    }

    public Bool(final boolean value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Bool bool = (Bool) o;

      return value == bool.value;
    }

    @Override
    public int hashCode() {
      return (value ? 1 : 0);
    }

    @Override
    public String toString() {
      return "" + this.value;
    }

    public Schema.TermV2 serialize() {
      return Schema.TermV2.newBuilder().setBool(this.value).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasBool()) {
        return Left(
            new Error.FormatError.DeserializationError("invalid Term kind, expected boolean"));
      } else {
        return Right(new Bool(term.getBool()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Bool(this.value);
    }
  }

  public static final class Set extends Term implements Serializable {
    private final HashSet<Term> value;

    public HashSet<Term> value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Set) {
        return this.value.equals(((Set) other).value);
      }
      return false;
    }

    public Set(final HashSet<Term> value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Set set = (Set) o;

      return value.equals(set.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }

    @Override
    public String toString() {
      return "" + value;
    }

    public Schema.TermV2 serialize() {
      Schema.TermSet.Builder s = Schema.TermSet.newBuilder();

      for (Term l : this.value) {
        s.addSet(l.serialize());
      }

      return Schema.TermV2.newBuilder().setSet(s).build();
    }

    public static Either<Error.FormatError, Term> deserializeV2(Schema.TermV2 term) {
      if (!term.hasSet()) {
        return Left(new Error.FormatError.DeserializationError("invalid Term kind, expected set"));
      } else {
        java.util.HashSet<Term> values = new HashSet<>();
        Schema.TermSet s = term.getSet();

        for (Schema.TermV2 l : s.getSetList()) {
          Either<Error.FormatError, Term> res = Term.deserializeEnumV2(l);
          if (res.isLeft()) {
            Error.FormatError e = res.getLeft();
            return Left(e);
          } else {
            Term value = res.get();

            if (value instanceof Variable) {
              return Left(
                  new Error.FormatError.DeserializationError("sets cannot contain variables"));
            }

            values.add(value);
          }
        }

        if (values.isEmpty()) {
          return Left(new Error.FormatError.DeserializationError("invalid Set value"));
        } else {
          return Right(new Set(values));
        }
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      HashSet<org.eclipse.biscuit.token.builder.Term> s = new HashSet<>();

      for (Term i : this.value) {
        s.add(i.toTerm(symbolTable));
      }

      return new org.eclipse.biscuit.token.builder.Term.Set(s);
    }
  }
}
