# Use the official PowerShell parser as a syntax frontend only. The resulting
# tree is serialized as inert data; user input is never executed by pwsh.
$ErrorActionPreference = 'Stop'

function Convert-Statements($statements) {
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($statement in $statements) {
        if ($statement -is [System.Management.Automation.Language.PipelineAst]) {
            $elements = [System.Collections.Generic.List[object]]::new()
            foreach ($element in $statement.PipelineElements) {
                if ($element -is [System.Management.Automation.Language.CommandAst] -and $element.Redirections.Count -eq 0) {
                    $words = [System.Collections.Generic.List[string]]::new()
                    foreach ($item in $element.CommandElements) {
                        # Extent.Text retains quoting and variable references so
                        # the Rust evaluator can apply the limited safe semantics.
                        if ($item -is [System.Management.Automation.Language.CommandParameterAst]) {
                            $words.Add('-' + $item.ParameterName)
                            if ($null -ne $item.Argument) { $words.Add($item.Argument.Extent.Text) }
                        } else {
                            $words.Add($item.Extent.Text)
                        }
                    }
                    $elements.Add(@{ kind = 'command'; words = @($words.ToArray()) })
                } elseif ($element -is [System.Management.Automation.Language.CommandExpressionAst] -and $element.Redirections.Count -eq 0) {
                    $elements.Add(@{ kind = 'expression'; text = $element.Expression.Extent.Text })
                } else {
                    throw 'This PowerShell pipeline element is not available in the virtual shell.'
                }
            }
            $items.Add(@{ kind = 'pipeline'; elements = @($elements.ToArray()) })
        } elseif ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and $statement.Operator.ToString() -eq 'Equals') {
            $items.Add(@{ kind = 'assignment'; left = $statement.Left.Extent.Text; right = $statement.Right.Extent.Text })
        } elseif ($statement -is [System.Management.Automation.Language.IfStatementAst]) {
            $clauses = [System.Collections.Generic.List[object]]::new()
            foreach ($clause in $statement.Clauses) {
                $clauses.Add(@{ condition = $clause.Item1.Extent.Text; body = @(Convert-Statements $clause.Item2.Statements) })
            }
            $elseBody = @()
            if ($null -ne $statement.ElseClause) { $elseBody = @(Convert-Statements $statement.ElseClause.Statements) }
            $items.Add(@{ kind = 'if'; clauses = @($clauses.ToArray()); else_body = $elseBody })
        } elseif ($statement -is [System.Management.Automation.Language.ForEachStatementAst]) {
            $items.Add(@{
                kind = 'for_each'
                variable = $statement.Variable.Extent.Text
                expression = $statement.Condition.Extent.Text
                body = @(Convert-Statements $statement.Body.Statements)
            })
        } elseif ($statement -is [System.Management.Automation.Language.ExitStatementAst]) {
            $items.Add(@{ kind = 'pipeline'; elements = @(@{ kind = 'command'; words = @('exit') }) })
        } else {
            throw 'This PowerShell statement is not available in the virtual shell.'
        }
    }
    return $items.ToArray()
}

while ($null -ne ($request = [Console]::In.ReadLine())) {
    $result = @{ error = $null; items = @() }
    try {
        $source = ConvertFrom-Json -InputObject $request -ErrorAction Stop
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $source, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) {
            $result.error = $parseErrors[0].Message
        } elseif ($null -eq $ast.EndBlock) {
            $result.error = 'Unsupported PowerShell input.'
        } else {
            $result.items = @(Convert-Statements $ast.EndBlock.Statements)
        }
    } catch {
        $result.error = $_.Exception.Message
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Compress -Depth 20))
    [Console]::Out.Flush()
}
