/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.List;
import java.util.Optional;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.format.SerializedBiscuit;

public final class SchemaVersion {
  public static int version(
      List<Fact> facts,
      List<Rule> rules,
      List<Check> checks,
      List<Scope> scopes,
      Optional<PublicKey> externalKey) {
    if (containsV6(facts, rules, checks)) {
      return SerializedBiscuit.DATALOG_3_3;
    }
    if (containsV5(externalKey)) {
      return SerializedBiscuit.DATALOG_3_2;
    }
    if (containsV4(rules, checks, scopes)) {
      return SerializedBiscuit.DATALOG_3_1;
    }
    return SerializedBiscuit.MIN_SCHEMA_VERSION;
  }

  public static Result<Void, Error.FormatError> checkCompatibility(
      int version,
      List<Fact> facts,
      List<Rule> rules,
      List<Check> checks,
      List<Scope> scopes,
      Optional<PublicKey> externalKey) {
    if (version < SerializedBiscuit.DATALOG_3_1 && containsV4(rules, checks, scopes)) {
      return Result.err(
          new Error.FormatError.DeserializationError(
              "v" + version + " blocks must not have v4 features"));
    }
    if (version < SerializedBiscuit.DATALOG_3_2 && containsV5(externalKey)) {
      return Result.err(
          new Error.FormatError.DeserializationError(
              "v" + version + " blocks must not have v5 features"));
    }
    if (version < SerializedBiscuit.DATALOG_3_3 && containsV6(facts, rules, checks)) {
      return Result.err(
          new Error.FormatError.DeserializationError(
              "v" + version + " blocks must not have v6 features"));
    }
    return Result.ok(null);
  }

  private static boolean containsV4(List<Rule> rules, List<Check> checks, List<Scope> scopes) {
    if (!scopes.isEmpty()) {
      return true;
    }
    for (Rule rule : rules) {
      if (!rule.scopes().isEmpty()) {
        return true;
      }
      if (containsV4Ops(rule.expressions())) {
        return true;
      }
    }

    for (Check check : checks) {
      if (check.kind() == Check.Kind.ALL) {
        return true;
      }
      for (Rule query : check.queries()) {
        if (!query.scopes().isEmpty()) {
          return true;
        }
        if (containsV4Ops(query.expressions())) {
          return true;
        }
      }
    }

    return false;
  }

  private static boolean containsV5(Optional<PublicKey> externalKey) {
    return externalKey.isPresent();
  }

  private static boolean containsV6(List<Fact> facts, List<Rule> rules, List<Check> checks) {
    for (Fact fact : facts) {
      if (containsV6Terms(fact.predicate().terms())) {
        return true;
      }
    }

    for (Rule rule : rules) {
      if (containsV6Ops(rule.expressions())) {
        return true;
      }
    }

    for (Check check : checks) {
      if (check.kind() == Check.Kind.REJECT) {
        return true;
      }
      for (Rule query : check.queries()) {
        if (containsV6Ops(query.expressions())) {
          return true;
        }
      }
    }

    return false;
  }

  private static boolean containsV4Ops(List<Expression> expressions) {
    for (Expression e : expressions) {
      for (Op op : e.getOps()) {
        if (op instanceof Op.Binary) {
          Op.Binary b = (Op.Binary) op;
          switch (b.getOp()) {
            case BitwiseAnd:
            case BitwiseOr:
            case BitwiseXor:
            case NotEqual:
              return true;
            default:
          }
        }
      }
    }
    return false;
  }

  private static boolean containsV6Ops(List<Expression> expressions) {
    for (Expression e : expressions) {
      for (Op op : e.getOps()) {
        if (op instanceof Op.Unary) {
          Op.Unary b = (Op.Unary) op;
          switch (b.getOp()) {
            case TypeOf:
              return true;
            default:
          }
        } else if (op instanceof Op.Binary) {
          Op.Binary b = (Op.Binary) op;
          switch (b.getOp()) {
            case HeterogeneousEqual:
            case HeterogeneousNotEqual:
            case LazyAnd:
            case LazyOr:
            case Get:
            case Any:
            case All:
            case TryOr:
              return true;
            default:
          }
        } else if (op instanceof Op.Closure) {
          return true;
        } else if (op instanceof Term.Null) {
          return true;
        } else if (op instanceof Term.Array) {
          return true;
        } else if (op instanceof Term.Map) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean containsV6Terms(List<Term> terms) {
    for (Term term : terms) {
      if (term instanceof Term.Null) {
        return true;
      } else if (term instanceof Term.Array) {
        return true;
      } else if (term instanceof Term.Map) {
        return true;
      }
    }
    return false;
  }
}
