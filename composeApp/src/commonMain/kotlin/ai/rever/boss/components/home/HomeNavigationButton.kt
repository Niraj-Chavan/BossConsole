package ai.rever.boss.components.home

import ai.rever.boss.components.overlays.HoverTooltipBox
import ai.rever.boss.plugin.ui.BossTheme
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.ButtonDefaults
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Home
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/** Window navigation, kept outside the list of closable tabs. */
@Composable
internal fun HomeNavigationButton(
    selected: Boolean,
    compact: Boolean = false,
    onClick: () -> Unit,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val hovered by interactionSource.collectIsHoveredAsState()
    HoverTooltipBox(text = "Go Home in this pane") {
        TextButton(
            onClick = onClick,
            interactionSource = interactionSource,
            modifier =
                (if (compact) Modifier.size(36.dp) else Modifier.fillMaxWidth())
                    .hoverable(interactionSource)
                    .semantics { this.selected = selected },
            colors =
                ButtonDefaults.textButtonColors(
                    backgroundColor = if (hovered) BossTheme.colors.raised.copy(alpha = 0.35f) else Color.Transparent,
                    contentColor = if (selected) MaterialTheme.colors.primary else BossTheme.colors.textPrimary,
                ),
        ) {
            Row(
                modifier = if (compact) Modifier else Modifier.fillMaxWidth().padding(horizontal = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    Icons.Outlined.Home,
                    contentDescription = if (compact) "Home" else null,
                    modifier = Modifier.size(18.dp),
                )
                if (!compact) {
                    Spacer(Modifier.width(8.dp))
                    Text("Home")
                }
            }
        }
    }
}
